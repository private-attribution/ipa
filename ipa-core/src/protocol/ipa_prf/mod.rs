use std::{num::NonZeroU32, ops::Add};

use generic_array::{ArrayLength, GenericArray};
use ipa_macros::Step;
use typenum::{Unsigned, U18};

use self::{quicksort::quicksort_ranges_by_key_insecure, shuffle::shuffle_inputs};
use crate::{
    error::{Error, UnwrapInfallible},
    ff::{boolean::Boolean, boolean_array::BA64, CustomArray, Field, PrimeField, Serializable},
    protocol::{
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, gen_prf_key},
            prf_sharding::{
                attribute_cap_aggregate, histograms_ranges_sortkeys, PrfShardedIpaInputRow,
            },
        },
        RecordId,
    },
    secret_sharing::{
        replicated::{malicious::ExtendableField, semi_honest::AdditiveShare as Replicated},
        SharedValue,
    },
};

mod boolean_ops;
pub mod prf_eval;
pub mod prf_sharding;

mod quicksort;
mod shuffle;

#[derive(Step)]
pub(crate) enum Step {
    ConvertFp25519,
    EvalPrf,
    ConvertInputRowsToPrf,
    Shuffle,
    SortByTimestamp,
}

#[derive(Debug)]
#[cfg_attr(test, derive(Clone, PartialEq, Eq))]
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
pub async fn oprf_ipa<C, BK, TV, TS, SS, F>(
    ctx: C,
    input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    BK: SharedValue + CustomArray<Element = Boolean> + Field,
    TV: SharedValue + CustomArray<Element = Boolean> + Field,
    TS: SharedValue + CustomArray<Element = Boolean> + Field,
    SS: SharedValue + CustomArray<Element = Boolean> + Field,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable,
{
    let shuffled = shuffle_inputs(ctx.narrow(&Step::Shuffle), input_rows).await?;
    let mut prfd_inputs =
        compute_prf_for_inputs(ctx.narrow(&Step::ConvertInputRowsToPrf), shuffled).await?;

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

    attribute_cap_aggregate::<C, BK, TV, TS, SS, Replicated<F>, F>(
        ctx,
        prfd_inputs,
        attribution_window_seconds,
        &histogram,
    )
    .await
}

#[tracing::instrument(name = "compute_prf_for_inputs", skip_all)]
async fn compute_prf_for_inputs<C, BK, TV, TS, F>(
    ctx: C,
    input_rows: Vec<OPRFIPAInputRow<BK, TV, TS>>,
) -> Result<Vec<PrfShardedIpaInputRow<BK, TV, TS>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    BK: SharedValue + CustomArray<Element = Boolean> + Field,
    TV: SharedValue + CustomArray<Element = Boolean> + Field,
    TS: SharedValue + CustomArray<Element = Boolean> + Field,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable,
{
    let ctx = ctx.set_total_records(input_rows.len());
    let convert_ctx = ctx.narrow(&Step::ConvertFp25519);
    let eval_ctx = ctx.narrow(&Step::EvalPrf);

    let prf_key = gen_prf_key(&convert_ctx);

    ctx.try_join(input_rows.into_iter().enumerate().map(|(idx, record)| {
        let convert_ctx = convert_ctx.clone();
        let eval_ctx = eval_ctx.clone();
        let prf_key = &prf_key;
        async move {
            let record_id = RecordId::from(idx);
            let elliptic_curve_pt =
                convert_to_fp25519::<_, BA64>(convert_ctx, record_id, &record.match_key).await?;
            let elliptic_curve_pt =
                eval_dy_prf(eval_ctx, record_id, prf_key, &elliptic_curve_pt).await?;

            Ok::<_, Error>(PrfShardedIpaInputRow {
                prf_of_match_key: elliptic_curve_pt,
                is_trigger_bit: record.is_trigger,
                breakdown_key: record.breakdown_key,
                trigger_value: record.trigger_value,
                timestamp: record.timestamp,
                sort_key: Replicated::ZERO,
            })
        }
    }))
    .await
}
#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use crate::{
        ff::{
            boolean_array::{BA20, BA3, BA5, BA8},
            Fp31,
        },
        protocol::ipa_prf::oprf_ipa,
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld},
    };

    #[test]
    fn semi_honest() {
        const EXPECTED: &[u128] = &[0, 2, 5, 0, 0, 0, 0, 0];

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<TestRawDataRecord> = vec![
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 5,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 2,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 10,
                    user_id: 12345,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 5,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 68362,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 20,
                    user_id: 68362,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 2,
                },
            ];

            let mut result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    oprf_ipa::<_, BA8, BA3, BA20, BA5, Fp31>(ctx, input_rows, None)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            result.truncate(EXPECTED.len());
            assert_eq!(
                result,
                EXPECTED
                    .iter()
                    .map(|i| Fp31::try_from(*i).unwrap())
                    .collect::<Vec<_>>()
            );
        });
    }
}
