use std::iter::repeat;

use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{boolean_array::BA64, GaloisField, Gf2, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    protocol::{
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::{
            boolean_ops::share_conversion_aby::convert_to_fp25519,
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

#[cfg(feature = "descriptive-gate")]
mod boolean_ops;
#[cfg(feature = "descriptive-gate")]
pub mod prf_eval;
pub mod prf_sharding;
#[cfg(feature = "descriptive-gate")]
pub mod shuffle;

#[derive(Step)]
pub(crate) enum Step {
    ConvertFp25519,
    EvalPrf,
}

#[derive(Debug)]
pub struct PrfIpaInputRow<BK: GaloisField, TV: GaloisField, TS: GaloisField> {
    pub match_key: Replicated<BA64>,
    pub is_trigger_bit: Replicated<Gf2>,
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
pub async fn oprf_ipa<C, BK, TV, TS, F>(
    ctx: C,
    input_rows: Vec<PrfIpaInputRow<BK, TV, TS>>,
    config: IpaQueryConfig,
) -> Result<Vec<Replicated<F>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    BK: GaloisField,
    TV: GaloisField,
    TS: GaloisField,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable,
{
    let user_cap: i32 = config.per_user_credit_cap.try_into().unwrap();
    assert!(
        user_cap & (user_cap - 1) == 0,
        "This code only works for a user cap which is a power of 2"
    );

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
        .parallel_join(input_rows.iter().zip(repeat(prf_key)).enumerate().map(
            |(idx, (record, prf_key))| {
                let convert_ctx = convert_ctx.clone();
                let eval_ctx = eval_ctx.clone();
                async move {
                    let record_id = RecordId::from(idx);
                    let prf_of_match_key =
                        convert_to_fp25519::<_, BA64>(convert_ctx, record_id, &record.match_key)
                            .await?;
                    eval_dy_prf(eval_ctx, record_id, &prf_key, &prf_of_match_key).await
                }
            },
        ))
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
    attribution_and_capping_and_aggregation::<C, BK, TV, TS, Replicated<F>, F>(
        ctx,
        pseudonymed_inputs,
        user_cap.ilog2().try_into().unwrap(),
        config.attribution_window_seconds,
        &histogram,
    )
    .await
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]

pub mod tests {
    use crate::{
        ff::Fp31,
        helpers::query::IpaQueryConfig,
        protocol::{ipa_prf::oprf_ipa, BreakdownKey, Timestamp, TriggerValue},
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
                    oprf_ipa::<_, BreakdownKey, TriggerValue, Timestamp, Fp31>(
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
