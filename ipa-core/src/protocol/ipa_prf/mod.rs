#[cfg(feature = "descriptive-gate")]
use std::iter::repeat;
use std::iter::zip;

#[cfg(feature = "descriptive-gate")]
use ipa_macros::Step;

#[cfg(feature = "descriptive-gate")]
use crate::{
    error::Error,
    ff::{boolean_array::BA64, CustomArray, Field, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    protocol::{
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::{
            boolean_ops::convert_to_fp25519,
            prf_eval::{eval_dy_prf, gen_prf_key},
            prf_sharding::{
                attribution_and_capping_and_aggregation, compute_histogram_of_users_with_row_count,
                PrfShardedIpaInputRow,
            },
        },
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
    },
};
use crate::{ff::boolean::Boolean, secret_sharing::WeakSharedValue};

#[cfg(feature = "descriptive-gate")]
mod boolean_ops;
#[cfg(feature = "descriptive-gate")]
pub mod prf_eval;
pub mod prf_sharding;
#[cfg(feature = "descriptive-gate")]
pub mod shuffle;

#[cfg(feature = "descriptive-gate")]
#[derive(Step)]
pub(crate) enum Step {
    ConvertFp25519,
    EvalPrf,
}

#[cfg(feature = "descriptive-gate")]
#[derive(Debug)]
pub struct PrfIpaInputRow<BK: WeakSharedValue, TV: WeakSharedValue, TS: WeakSharedValue> {
    pub match_key: Replicated<BA64>,
    pub is_trigger_bit: Replicated<Boolean>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
}

/// IPA OPRF Protocol
///
/// We return `Replicated<F>` as output.
/// This protocol does following steps
/// 1. Shuffles the input (TBD)
/// 2. Converts boolean arrays of match keys to elliptical values
/// 3. Computes OPRF on the match keys and reveals the OPRF
/// 4. Sorts inputs based on reveal oprf and timestamp (TBD)
/// 5. Computes the attribution, caps results and aggregates
/// # Errors
/// Propagates errors from config issues or while running the protocol
/// # Panics
/// Propagates errors from config issues or while running the protocol
#[cfg(feature = "descriptive-gate")]
pub async fn oprf_ipa<C, BK, TV, TS, SS, F>(
    ctx: C,
    input_rows: Vec<PrfIpaInputRow<BK, TV, TS>>,
    config: IpaQueryConfig,
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    BK: WeakSharedValue + CustomArray<Element = Boolean> + Field,
    TV: WeakSharedValue + CustomArray<Element = Boolean> + Field,
    TS: WeakSharedValue + CustomArray<Element = Boolean> + Field,
    SS: WeakSharedValue + CustomArray<Element = Boolean> + Field,
    for<'a> &'a Replicated<SS>: IntoIterator<Item = Replicated<Boolean>>,
    for<'a> &'a Replicated<TS>: IntoIterator<Item = Replicated<Boolean>>,
    for<'a> &'a Replicated<TV>: IntoIterator<Item = Replicated<Boolean>>,
    for<'a> &'a Replicated<BK>: IntoIterator<Item = Replicated<Boolean>>,
    for<'a> <&'a Replicated<SS> as IntoIterator>::IntoIter: Send,
    for<'a> <&'a Replicated<TV> as IntoIterator>::IntoIter: Send,
    for<'a> <&'a Replicated<TS> as IntoIterator>::IntoIter: Send,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable,
{
    // TODO (richaj): Add shuffle either before the protocol starts or, after converting match keys to elliptical curve.
    // We might want to do it earlier as that's a cleaner code

    let convert_ctx = ctx
        .narrow(&Step::ConvertFp25519)
        .set_total_records(input_rows.len());
    let eval_ctx = ctx
        .narrow(&Step::EvalPrf)
        .set_total_records(input_rows.len());

    let prf_key = gen_prf_key(&convert_ctx);

    let pseudonymed_user_ids = ctx
        .parallel_join(
            input_rows
                .iter()
                .zip(zip(
                    repeat(prf_key),
                    zip(repeat(convert_ctx), repeat(eval_ctx)),
                ))
                .enumerate()
                .map(
                    |(idx, (record, (prf_key, (convert_ctx, eval_ctx))))| async move {
                        let record_id = RecordId::from(idx);
                        let prf_of_match_key = convert_to_fp25519::<_, BA64>(
                            convert_ctx,
                            record_id,
                            &record.match_key,
                        )
                        .await?;
                        eval_dy_prf(eval_ctx, record_id, &prf_key, &prf_of_match_key).await
                    },
                ),
        )
        .await?;
    let pseudonymed_inputs = input_rows
        .into_iter()
        .zip(pseudonymed_user_ids.into_iter())
        .map(|(input, pseudonym)| PrfShardedIpaInputRow {
            prf_of_match_key: pseudonym,
            is_trigger_bit: input.is_trigger_bit,
            breakdown_key: input.breakdown_key,
            trigger_value: input.trigger_value,
            timestamp: input.timestamp,
        })
        .collect::<Vec<_>>();

    let histogram = compute_histogram_of_users_with_row_count(&pseudonymed_inputs);

    // TODO (richaj) : Call quicksort on match keys followed by timestamp before calling attribution logic
    attribution_and_capping_and_aggregation::<C, BK, TV, TS, SS, Replicated<F>, F>(
        ctx,
        pseudonymed_inputs,
        config.attribution_window_seconds,
        &histogram,
    )
    .await
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use crate::{
        ff::{
            boolean_array::{BA20, BA3, BA5, BA8},
            Fp31,
        },
        helpers::query::IpaQueryConfig,
        protocol::ipa_prf::oprf_ipa,
        test_executor::run,
        test_fixture::{ipa::TestRawDataRecord, Reconstruct, Runner, TestWorld},
    };

    #[test]
    fn semi_honest() {
        const PER_USER_CAP: u32 = 16;
        const EXPECTED: &[u128] = &[0, 2, 5, 0, 0, 0, 0, 0];
        const MAX_BREAKDOWN_KEY: u32 = 8;
        const NUM_MULTI_BITS: u32 = 3;

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
                    timestamp: 0,
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
                    oprf_ipa::<_, BA8, BA3, BA20, BA5, Fp31>(
                        ctx,
                        input_rows,
                        IpaQueryConfig::no_window(PER_USER_CAP, MAX_BREAKDOWN_KEY, NUM_MULTI_BITS),
                    )
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
