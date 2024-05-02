use std::{array, convert::Infallible, num::NonZeroU32, ops::Add};

use futures_util::TryStreamExt;
use generic_array::{ArrayLength, GenericArray};
use ipa_macros::Step;
use typenum::{Unsigned, U18};

use self::{quicksort::quicksort_ranges_by_key_insecure, shuffle::shuffle_inputs};
use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{
        boolean::Boolean, boolean_array::BA64, ec_prime_field::Fp25519, ArrayBuild, ArrayBuilder,
        CustomArray, Serializable, U128Conversions,
    },
    helpers::stream::{process_slice_by_chunks, ChunkData, TryFlattenItersExt},
    protocol::{
        basics::{BooleanArrayMul, BooleanProtocols, SecureMul},
        context::{
            Context, SemiHonestContext, UpgradableContext, UpgradedContext,
            UpgradedSemiHonestContext,
        },
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, gen_prf_key},
            prf_sharding::{
                attribute_cap_aggregate, histograms_ranges_sortkeys, PrfShardedIpaInputRow,
            },
        },
        prss::FromPrss,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        SharedValue, TransposeFrom,
    },
    seq_join::seq_join,
    sharding::NotSharded,
    BoolVector,
};

mod aggregation;
mod boolean_ops;
pub mod prf_eval;
pub mod prf_sharding;

#[cfg(all(test, unit_test))]
mod malicious_security;
mod quicksort;
mod shuffle;

/// Match key size
pub const MK_BITS: usize = 64;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 64;

/// Vectorization dimension for aggregation.
pub const AGG_CHUNK: usize = 256;

#[derive(Step)]
pub(crate) enum Step {
    ConvertFp25519,
    EvalPrf,
    ConvertInputRowsToPrf,
    Shuffle,
    SortByTimestamp,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct OPRFIPAInputRow<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
    pub match_key: Replicated<BA64>,
    pub is_trigger: Replicated<Boolean>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
}

impl<BK: SharedValue, TV: SharedValue, TS: SharedValue> Serializable for OPRFIPAInputRow<BK, TV, TS>
where
    Replicated<BK>: Serializable,
    Replicated<TV>: Serializable,
    Replicated<TS>: Serializable,
    <Replicated<BK> as Serializable>::Size: Add<U18>,
    <Replicated<TS> as Serializable>::Size:
        Add<<<Replicated<BK> as Serializable>::Size as Add<U18>>::Output>,
    <Replicated<TV> as Serializable>::Size: Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >,
    <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >>::Output: ArrayLength,
{
    type Size = <<Replicated<TV> as Serializable>::Size as Add<
        <<Replicated<TS> as Serializable>::Size as Add<
            <<Replicated<BK> as Serializable>::Size as Add<U18>>::Output,
        >>::Output,
    >>::Output;
    type DeserializationError = Error;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;
        let it_sz = <Replicated<Boolean> as Serializable>::Size::USIZE;

        self.match_key
            .serialize(GenericArray::from_mut_slice(&mut buf[..mk_sz]));

        self.timestamp
            .serialize(GenericArray::from_mut_slice(&mut buf[mk_sz..mk_sz + ts_sz]));

        self.breakdown_key.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz..mk_sz + ts_sz + bk_sz],
        ));

        self.trigger_value.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz + bk_sz..mk_sz + ts_sz + bk_sz + tv_sz],
        ));

        self.is_trigger.serialize(GenericArray::from_mut_slice(
            &mut buf[mk_sz + ts_sz + bk_sz + tv_sz..mk_sz + ts_sz + bk_sz + tv_sz + it_sz],
        ));
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError> {
        let mk_sz = <Replicated<BA64> as Serializable>::Size::USIZE;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;
        let it_sz = <Replicated<Boolean> as Serializable>::Size::USIZE;

        let match_key = Replicated::<BA64>::deserialize(GenericArray::from_slice(&buf[..mk_sz]))
            .unwrap_infallible();
        let timestamp =
            Replicated::<TS>::deserialize(GenericArray::from_slice(&buf[mk_sz..mk_sz + ts_sz]))
                .map_err(|e| Error::ParseError(e.into()))?;
        let breakdown_key = Replicated::<BK>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz..mk_sz + ts_sz + bk_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;
        let trigger_value = Replicated::<TV>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz + bk_sz..mk_sz + ts_sz + bk_sz + tv_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;
        let is_trigger = Replicated::<Boolean>::deserialize(GenericArray::from_slice(
            &buf[mk_sz + ts_sz + bk_sz + tv_sz..mk_sz + ts_sz + bk_sz + tv_sz + it_sz],
        ))
        .map_err(|e| Error::ParseError(e.into()))?;

        Ok(Self {
            match_key,
            is_trigger,
            breakdown_key,
            trigger_value,
            timestamp,
        })
    }
}

/// IPA OPRF Protocol
///
/// The output of this function is a vector of secret-shared totals, one per breakdown key
/// This protocol performs the following steps
/// 1. Converts secret-sharings of boolean arrays to secret-sharings of elliptic curve points
/// 2. Generates a random number of "dummy records" (needed to mask the information that will
///    be revealed in a later step, and thereby provide a differential privacy guarantee on that
///    information leakage) (TBD)
/// 3. Shuffles the input
/// 4. Computes an OPRF of these elliptic curve points and reveals this "pseudonym"
/// 5. Groups together rows with the same OPRF, and then obliviously sorts each group by the
///    secret-shared timestamp
/// 6. Attributes trigger events to source events
/// 7. Caps each user's total contribution to the final result
/// 8. Aggregates the contributions of all users
/// 9. Adds random noise to the total for each breakdown key (to provide a differential
///    privacy guarantee) (TBD)
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
pub async fn oprf_ipa<'ctx, BK, TV, HV, TS, SS, const B: usize>(
    ctx: SemiHonestContext<'ctx>,
    input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    BK: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    TV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    HV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    TS: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    SS: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, Boolean, B>,
    Replicated<BK>: BooleanArrayMul,
    Replicated<TS>: BooleanArrayMul,
    Replicated<TV>: BooleanArrayMul,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<TV>>, Error = LengthError>,
    Vec<BitDecomposed<Replicated<Boolean, B>>>: for<'a> TransposeFrom<
        &'a [BitDecomposed<Replicated<Boolean, AGG_CHUNK>>],
        Error = Infallible,
    >,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    let shuffled = shuffle_inputs(ctx.narrow(&Step::Shuffle), input_rows).await?;
    let mut prfd_inputs =
        compute_prf_for_inputs(ctx.narrow(&Step::ConvertInputRowsToPrf), &shuffled).await?;

    prfd_inputs.sort_by(|a, b| a.prf_of_match_key.cmp(&b.prf_of_match_key));

    let (histogram, ranges) = histograms_ranges_sortkeys(&mut prfd_inputs);
    quicksort_ranges_by_key_insecure(
        ctx.narrow(&Step::SortByTimestamp),
        &mut prfd_inputs,
        false,
        |x| &x.sort_key,
        ranges,
    )
    .await?;

    attribute_cap_aggregate::<_, _, _, _, SS, B>(
        ctx,
        prfd_inputs,
        attribution_window_seconds,
        &histogram,
    )
    .await
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
async fn compute_prf_for_inputs<C, BK, TV, TS>(
    ctx: C,
    input_rows: &[OPRFIPAInputRow<BK, TV, TS>],
) -> Result<Vec<PrfShardedIpaInputRow<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    BK: SharedValue + CustomArray<Element = Boolean>,
    TV: SharedValue + CustomArray<Element = Boolean>,
    TS: SharedValue + CustomArray<Element = Boolean>,
    Replicated<Boolean, PRF_CHUNK>: BooleanProtocols<C, Boolean, PRF_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>: SecureMul<C> + FromPrss,
{
    let ctx = ctx.set_total_records((input_rows.len() + PRF_CHUNK - 1) / PRF_CHUNK);
    let convert_ctx = ctx.narrow(&Step::ConvertFp25519);
    let eval_ctx = ctx.narrow(&Step::EvalPrf);

    let prf_key = gen_prf_key(&convert_ctx);

    seq_join(
        ctx.active_work(),
        process_slice_by_chunks(
            input_rows,
            move |idx, records: ChunkData<_, PRF_CHUNK>| {
                let convert_ctx = convert_ctx.clone();
                let eval_ctx = eval_ctx.clone();
                let prf_key = prf_key.clone();

                async move {
                    let record_id = RecordId::from(idx);
                    let input_match_keys: &dyn Fn(usize) -> Replicated<BA64> =
                        &|i| records[i].match_key.clone();
                    let mut match_keys_builder = <BoolVector!(64, PRF_CHUNK)>::builder();
                    for _ in 0..MK_BITS {
                        match_keys_builder.push(Replicated::<Boolean, PRF_CHUNK>::ZERO);
                    }
                    let mut match_keys = match_keys_builder.build();
                    match_keys
                        .transpose_from(input_match_keys)
                        .unwrap_infallible();
                    let curve_pts = convert_to_fp25519::<
                        _,
                        BoolVector!(64, PRF_CHUNK),
                        BoolVector!(256, PRF_CHUNK),
                        PRF_CHUNK,
                    >(convert_ctx, record_id, match_keys)
                    .await?;

                    let prf_of_match_keys =
                        eval_dy_prf::<_, PRF_CHUNK>(eval_ctx, record_id, &prf_key, curve_pts)
                            .await?;

                    Ok(array::from_fn(|i| {
                        let OPRFIPAInputRow {
                            match_key: _,
                            is_trigger,
                            breakdown_key,
                            trigger_value,
                            timestamp,
                        } = &records[i];

                        PrfShardedIpaInputRow {
                            prf_of_match_key: prf_of_match_keys[i],
                            is_trigger_bit: is_trigger.clone(),
                            breakdown_key: breakdown_key.clone(),
                            trigger_value: trigger_value.clone(),
                            timestamp: timestamp.clone(),
                            sort_key: Replicated::ZERO,
                        }
                    }))
                }
            },
            || OPRFIPAInputRow {
                match_key: Replicated::<BA64>::ZERO,
                is_trigger: Replicated::<Boolean>::ZERO,
                breakdown_key: Replicated::<BK>::ZERO,
                trigger_value: Replicated::<TV>::ZERO,
                timestamp: Replicated::<TS>::ZERO,
            },
        ),
    )
    .try_flatten_iters()
    .try_collect()
    .await
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use crate::{
        ff::{
            boolean_array::{BA16, BA20, BA3, BA5, BA8},
            U128Conversions,
        },
        protocol::ipa_prf::oprf_ipa,
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld},
    };

    fn test_input(
        timestamp: u64,
        user_id: u64,
        is_trigger_report: bool,
        breakdown_key: u32,
        trigger_value: u32,
    ) -> TestRawDataRecord {
        TestRawDataRecord {
            timestamp,
            user_id,
            is_trigger_report,
            breakdown_key,
            trigger_value,
        }
    }

    #[test]
    fn semi_honest() {
        const EXPECTED: &[u128] = &[0, 2, 5, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ];

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA8, BA3, BA16, BA20, BA5, 256>(ctx, input_rows, None)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }

    // Test that IPA tolerates duplicate timestamps among a user's records. The end-to-end test
    // harness does not generate data like this because the attribution result is non-deterministic.
    // To make the output deterministic for this case, all of the duplicate timestamp records are
    // identical.
    //
    // Don't run this with shuttle because it is slow and is unlikely to provide different coverage
    // than the previous test.
    #[cfg(not(feature = "shuttle"))]
    #[test]
    fn duplicate_timestamps() {
        use rand::{seq::SliceRandom, thread_rng};

        const EXPECTED: &[u128] = &[0, 2, 10, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let mut records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ];

            records.shuffle(&mut thread_rng());

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA8, BA3, BA16, BA20, BA5, 256>(ctx, input_rows, None)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>(),
                EXPECTED,
            );
        });
    }
}
