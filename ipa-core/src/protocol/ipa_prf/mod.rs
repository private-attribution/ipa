use std::{
    convert::Infallible,
    iter::{self, zip},
    num::NonZeroU32,
    ops::Add,
};

use futures::{stream, StreamExt, TryStreamExt};
use generic_array::{ArrayLength, GenericArray};
use typenum::{Const, Unsigned, U18};

use self::{quicksort::quicksort_ranges_by_key_insecure, shuffle::shuffle_inputs};
use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA5, BA64, BA8},
        ec_prime_field::Fp25519,
        Serializable, U128Conversions,
    },
    helpers::{
        stream::{div_round_up, process_slice_by_chunks, Chunk, ChunkData, TryFlattenItersExt},
        TotalRecords,
    },
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
};

pub(crate) mod aggregation;
pub mod boolean_ops;
pub mod oprf_padding;
pub mod prf_eval;
pub mod prf_sharding;

#[cfg(all(test, unit_test))]
mod malicious_security;
mod quicksort;
pub(crate) mod shuffle;
pub(crate) mod step;
#[cfg(all(test, unit_test))]
pub mod validation_protocol;

/// Match key type
pub type MatchKey = BA64;
/// Match key size
pub const MK_BITS: usize = BA64::BITS as usize;

// In theory, we could support (runtime-configured breakdown count) ≤ (compile-time breakdown count)
// ≤ 2^|bk|, with all three values distinct, but at present, there is no runtime configuration and
// the latter two must be equal. The implementation of `move_single_value_to_bucket` does support a
// runtime-specified count via the `breakdown_count` parameter, and implements a runtime check of
// its value.
//
// It would usually be more appropriate to make `MAX_BREAKDOWNS` an associated constant rather than
// a const parameter. However, we want to use it to enforce a correct pairing of the `BK` type
// parameter and the `B` const parameter, and specifying a constraint like
// `BreakdownKey<MAX_BREAKDOWNS = B>` on an associated constant is not currently supported. (Nor is
// supplying an associated constant `<BK as BreakdownKey>::MAX_BREAKDOWNS` as the value of a const
// parameter.) Structured the way we have it, it probably doesn't make sense to use the
// `BreakdownKey` trait in places where the `B` const parameter is not already available.
pub trait BreakdownKey<const MAX_BREAKDOWNS: usize>: BooleanArray + U128Conversions {}
impl BreakdownKey<32> for BA5 {}
impl BreakdownKey<256> for BA8 {}

/// Vectorization dimension for share conversion
pub const CONV_CHUNK: usize = 256;

/// Vectorization dimension for PRF
pub const PRF_CHUNK: usize = 16;

/// Vectorization dimension for aggregation.
pub const AGG_CHUNK: usize = 256;

/// Vectorization dimension for sort.
pub const SORT_CHUNK: usize = 256;

use step::IpaPrfStep as Step;

use crate::{
    helpers::query::DpParams,
    protocol::{context::Validator, dp::dp_for_histogram},
};

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct OPRFIPAInputRow<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
    pub match_key: Replicated<MatchKey>,
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
        let mk_sz = <Replicated<MatchKey> as Serializable>::Size::USIZE;
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
        let mk_sz = <Replicated<MatchKey> as Serializable>::Size::USIZE;
        let ts_sz = <Replicated<TS> as Serializable>::Size::USIZE;
        let bk_sz = <Replicated<BK> as Serializable>::Size::USIZE;
        let tv_sz = <Replicated<TV> as Serializable>::Size::USIZE;
        let it_sz = <Replicated<Boolean> as Serializable>::Size::USIZE;

        let match_key =
            Replicated::<MatchKey>::deserialize(GenericArray::from_slice(&buf[..mk_sz]))
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
///    privacy guarantee)
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
pub async fn oprf_ipa<'ctx, BK, TV, HV, TS, const SS_BITS: usize, const B: usize>(
    ctx: SemiHonestContext<'ctx>,
    input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
    dp_params: DpParams,
) -> Result<Vec<Replicated<HV>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, B>,
    for<'a> Replicated<BK>: BooleanArrayMul<UpgradedSemiHonestContext<'a, NotSharded, Boolean>>,
    for<'a> Replicated<TS>: BooleanArrayMul<UpgradedSemiHonestContext<'a, NotSharded, Boolean>>,
    for<'a> Replicated<TV>: BooleanArrayMul<UpgradedSemiHonestContext<'a, NotSharded, Boolean>>,
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
    if input_rows.is_empty() {
        return Ok(vec![Replicated::ZERO; B]);
    }
    let shuffled = shuffle_inputs(ctx.narrow(&Step::Shuffle), input_rows).await?;
    let mut prfd_inputs = compute_prf_for_inputs(ctx.clone(), &shuffled).await?;

    prfd_inputs.sort_by(|a, b| a.prf_of_match_key.cmp(&b.prf_of_match_key));

    let (histogram, ranges) = histograms_ranges_sortkeys(&mut prfd_inputs);
    if histogram.len() == 1 {
        // No user has more than one record.
        return Ok(vec![Replicated::ZERO; B]);
    }
    quicksort_ranges_by_key_insecure(
        ctx.narrow(&Step::SortByTimestamp),
        &mut prfd_inputs,
        false,
        |x| &x.sort_key,
        ranges,
    )
    .await?;

    let histogram = attribute_cap_aggregate::<_, _, _, _, SS_BITS, B>(
        ctx.narrow(&Step::Attribution),
        prfd_inputs,
        attribution_window_seconds,
        &histogram,
    )
    .await?;

    let dp_validator = ctx.narrow(&Step::DP).validator::<Boolean>();
    let dp_ctx: UpgradedSemiHonestContext<_, _> = dp_validator.context();

    let noisy_histogram =
        dp_for_histogram::<_, B, HV, SS_BITS>(dp_ctx, histogram, dp_params).await?;
    Ok(noisy_histogram)
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
async fn compute_prf_for_inputs<C, BK, TV, TS>(
    ctx: C,
    input_rows: &[OPRFIPAInputRow<BK, TV, TS>],
) -> Result<Vec<PrfShardedIpaInputRow<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    <C as UpgradableContext>::DZKPValidator: Send + Sync,
    C::UpgradedContext<Boolean>: UpgradedContext<Field = Boolean, Share = Replicated<Boolean>>,
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
    Replicated<Boolean, CONV_CHUNK>:
        BooleanProtocols<<C as UpgradableContext>::DZKPUpgradedContext, CONV_CHUNK>,
    Replicated<Fp25519, PRF_CHUNK>: SecureMul<C> + FromPrss,
{
    let conv_records =
        TotalRecords::specified(div_round_up(input_rows.len(), Const::<CONV_CHUNK>))?;
    let eval_records = TotalRecords::specified(div_round_up(input_rows.len(), Const::<PRF_CHUNK>))?;
    let convert_ctx = ctx
        .narrow(&Step::ConvertFp25519)
        .set_total_records(conv_records);
    let eval_ctx = ctx.narrow(&Step::EvalPrf).set_total_records(eval_records);

    let prf_key = gen_prf_key(&eval_ctx);

    let curve_pts = seq_join(
        ctx.active_work(),
        process_slice_by_chunks(
            input_rows,
            move |idx, records: ChunkData<_, CONV_CHUNK>| {
                let record_id = RecordId::from(idx);
                let convert_ctx = convert_ctx.clone();
                let input_match_keys: &dyn Fn(usize) -> Replicated<MatchKey> =
                    &|i| records[i].match_key.clone();
                let mut match_keys: BitDecomposed<Replicated<Boolean, 256>> =
                    BitDecomposed::new(iter::empty());
                match_keys
                    .transpose_from(input_match_keys)
                    .unwrap_infallible();
                convert_to_fp25519::<_, CONV_CHUNK, PRF_CHUNK>(convert_ctx, record_id, match_keys)
            },
            || OPRFIPAInputRow {
                match_key: Replicated::<MatchKey>::ZERO,
                is_trigger: Replicated::<Boolean>::ZERO,
                breakdown_key: Replicated::<BK>::ZERO,
                trigger_value: Replicated::<TV>::ZERO,
                timestamp: Replicated::<TS>::ZERO,
            },
        ),
    )
    .map_ok(Chunk::unpack::<PRF_CHUNK>)
    .try_flatten_iters()
    .try_collect::<Vec<_>>()
    .await?;

    let prf_of_match_keys = seq_join(
        ctx.active_work(),
        stream::iter(curve_pts).enumerate().map(|(i, curve_pts)| {
            let record_id = RecordId::from(i);
            let eval_ctx = eval_ctx.clone();
            let prf_key = &prf_key;
            curve_pts
                .then(move |pts| eval_dy_prf::<_, PRF_CHUNK>(eval_ctx, record_id, prf_key, pts))
        }),
    )
    .try_collect::<Vec<_>>()
    .await?;

    Ok(zip(input_rows, prf_of_match_keys.into_iter().flatten())
        .map(|(input, prf_of_match_key)| {
            let OPRFIPAInputRow {
                match_key: _,
                is_trigger,
                breakdown_key,
                trigger_value,
                timestamp,
            } = &input;

            PrfShardedIpaInputRow {
                prf_of_match_key,
                is_trigger_bit: is_trigger.clone(),
                breakdown_key: breakdown_key.clone(),
                trigger_value: trigger_value.clone(),
                timestamp: timestamp.clone(),
                sort_key: Replicated::ZERO,
            }
        })
        .collect())
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {

    use crate::{
        ff::{
            boolean_array::{BA16, BA20, BA3, BA5, BA8},
            U128Conversions,
        },
        helpers::query::DpParams,
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
            let dp_params = DpParams::NoDp;

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA5, BA3, BA16, BA20, 5, 32>(ctx, input_rows, None, dp_params)
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

    #[test]
    fn semi_honest_with_dp() {
        println!("Running semi_honest_with_dp");
        run(|| async {
            const SS_BITS: usize = 5;
            let world = TestWorld::default();
            let expected: Vec<u32> = vec![0, 2, 5, 0, 0, 0, 0, 0];
            let epsilon = 3.1;
            let dp_params = DpParams::WithDp { epsilon };
            let per_user_credit_cap = 2_f64.powi(i32::try_from(SS_BITS).unwrap());

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(5, 12345, false, 2, 0),
                test_input(10, 12345, true, 0, 5),
                test_input(0, 68362, false, 1, 0),
                test_input(20, 68362, true, 0, 2),
            ];

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA5, BA3, BA16, BA20, SS_BITS, 32>(ctx, input_rows, None, dp_params)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(expected.len());
            let num_bernoulli = crate::protocol::dp::find_smallest_num_bernoulli(
                epsilon,
                0.5,
                1e-6,
                1.0,
                1.0,
                per_user_credit_cap,
                per_user_credit_cap,
                per_user_credit_cap,
            );
            let mean: f64 = f64::from(num_bernoulli) * 0.5; // n * p
            let standard_deviation: f64 = (f64::from(num_bernoulli) * 0.5 * 0.5).sqrt(); //  sqrt(n * (p) * (1-p))
            println!(
                "In semi_honest_with_dp:  mean = {mean}, standard_deviation = {standard_deviation}"
            );
            let result_u32: Vec<u32> = result
                .iter()
                .map(|&v| u32::try_from(v.as_u128()).unwrap())
                .collect::<Vec<_>>();

            println!(
                "in test: semi_honest_with_dp. len result = {} and expected len =  {}",
                result_u32.len(),
                expected.len()
            );
            assert!(result_u32.len() == expected.len());
            for (index, actual_u128) in result_u32.iter().enumerate() {
                println!("actual = {actual_u128}, expected = {}", expected[index]);
                assert!(
                    f64::from(*actual_u128) - mean
                        > f64::from(expected[index]) - 5.0 * standard_deviation
                        && f64::from(*actual_u128) - mean
                            < f64::from(expected[index]) + 5.0 * standard_deviation
                , "DP result was more than 5 standard deviations of the noise from the expected result"
                );
            }
        });
    }

    #[test]
    fn semi_honest_empty() {
        const EXPECTED: &[u128] = &[0, 0, 0, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![];
            let dp_params = DpParams::NoDp;

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA5, BA3, BA8, BA20, 5, 32>(ctx, input_rows, None, dp_params)
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

    #[test]
    fn semi_honest_degenerate() {
        const EXPECTED: &[u128] = &[0, 0, 0, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                test_input(0, 12345, false, 1, 0),
                test_input(0, 68362, false, 1, 0),
            ];
            let dp_params = DpParams::NoDp;

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA5, BA3, BA8, BA20, 5, 32>(ctx, input_rows, None, dp_params)
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

        use crate::ff::boolean_array::{BA16, BA8};

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
            let dp_params = DpParams::NoDp;
            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<BA8, BA3, BA16, BA20, 5, 256>(ctx, input_rows, None, dp_params)
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
