use std::collections::HashMap;

use futures::stream;
use futures_util::{StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::{boolean::Boolean, boolean_array::BooleanArray, ArrayAccess},
    helpers::TotalRecords,
    protocol::{
        boolean::step::EightBitStep,
        context::{
            dzkp_validator::{DZKPValidator, TARGET_PROOF_SIZE},
            Context, DZKPContext, DZKPUpgraded, MaliciousProtocolSteps, UpgradableContext,
        },
        hybrid::step::{AggregateReportsStep, HybridStep},
        ipa_prf::boolean_ops::addition_sequential::integer_add,
        BooleanProtocols,
    },
    report::hybrid::{AggregateableHybridReport, PrfHybridReport},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
    seq_join::{seq_join, SeqJoin},
};

/// This protocol is used to aggregate `PRFHybridReports` and returns `AggregateableHybridReports`.
/// It groups all the reports by the PRF of the `match_key`, finds all reports from `match_keys`
/// with that provided exactly 2 reports, then adds those 2 reports.
pub async fn aggregate_reports<BK, V, C>(
    ctx: C,
    reports: Vec<PrfHybridReport<BK, V>>,
) -> Result<Vec<AggregateableHybridReport<BK, V>>, Error>
where
    C: UpgradableContext,
    BK: SharedValue + BooleanArray,
    V: SharedValue + BooleanArray,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
{
    let mut reports_by_matchkey = HashMap::with_capacity(reports.len() / 2);

    // build a hashmap of match_key -> ([AggregateableHybridReport;2], count)
    // if count ever exceeds 2, we drop reports, but keep counting
    // an honest client and report collector will only submit
    // one report with a breakdown key and one report with a value.
    // if there are less, it's unattributed. if more, something went wrong.
    for report in reports {
        let match_key = report.match_key;
        let entry = reports_by_matchkey.entry(match_key).or_insert((
            [
                AggregateableHybridReport::<BK, V>::ZERO,
                AggregateableHybridReport::<BK, V>::ZERO,
            ],
            0,
        ));
        if entry.1 == 0 {
            // If the count is 0, replace the first element with the new report
            entry.0[0] = report.into();
            entry.1 += 1;
        } else if entry.1 == 1 {
            // If the count is 1, replace the second element with the new report
            entry.0[1] = report.into();
            entry.1 += 1;
        } else {
            // If the count is 2 or more, increment the counter and drop the report
            entry.1 += 1;
        }
    }

    // we only keep the reports from match_keys that provided exactly 2 reports
    let report_pairs: Vec<[AggregateableHybridReport<BK, V>; 2]> = reports_by_matchkey
        .into_iter()
        .filter_map(|(_, v)| if v.1 == 2 { Some(v.0) } else { None })
        .collect::<Vec<_>>();

    let chunk_size = TARGET_PROOF_SIZE;

    let dzkp_validator = ctx.clone().dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &HybridStep::GroupBySum,
            validate: &HybridStep::GroupBySumValidate,
        },
        std::cmp::min(ctx.active_work().get(), chunk_size.next_power_of_two()),
    );

    let ctx = dzkp_validator
        .context()
        .set_total_records(TotalRecords::specified(report_pairs.len())?);

    let agg_work = stream::iter(report_pairs)
        .enumerate()
        .map(|(idx, reports)| {
            let agg_ctx = ctx.clone();
            async move {
                let (breakdown_key, _) = integer_add::<_, EightBitStep, 1>(
                    agg_ctx.narrow(&AggregateReportsStep::AddBK),
                    idx.into(),
                    &reports[0].breakdown_key.to_bits(),
                    &reports[1].breakdown_key.to_bits(),
                )
                .await?;
                let (value, _) = integer_add::<_, EightBitStep, 1>(
                    agg_ctx.narrow(&AggregateReportsStep::AddV),
                    idx.into(),
                    &reports[0].value.to_bits(),
                    &reports[1].value.to_bits(),
                )
                .await?;
                agg_ctx.validate_record(idx.into()).await?;
                Ok::<_, Error>(AggregateableHybridReport::<BK, V> {
                    match_key: (),
                    breakdown_key: breakdown_key.collect_bits(),
                    value: value.collect_bits(),
                })
            }
        });

    let agg_result = seq_join(ctx.active_work(), agg_work)
        .try_collect::<Vec<_>>()
        .await?;
    Ok(agg_result)
}

#[cfg(all(test, unit_test, feature = "in-memory-infra"))]
pub mod test {
    use super::aggregate_reports;
    use crate::{
        ff::boolean_array::{BA3, BA8},
        report::hybrid::{
            AggregateableHybridReport, IndistinguishableHybridReport, PrfHybridReport,
        },
        test_executor::run,
        test_fixture::{hybrid::TestHybridRecord, Runner, TestWorld, TestWorldConfig, WithShards},
    };

    #[test]
    fn aggregate_reports_test() {
        run(|| async {
            let records = vec![
                TestHybridRecord::TestImpression {
                    match_key: 12345,
                    breakdown_key: 2,
                },
                TestHybridRecord::TestImpression {
                    match_key: 23456,
                    breakdown_key: 4,
                },
                TestHybridRecord::TestConversion {
                    match_key: 23456,
                    value: 1,
                }, // attributed
                TestHybridRecord::TestImpression {
                    match_key: 45678,
                    breakdown_key: 3,
                },
                TestHybridRecord::TestConversion {
                    match_key: 45678,
                    value: 2,
                }, // attributed
                TestHybridRecord::TestImpression {
                    match_key: 56789,
                    breakdown_key: 5,
                },
                TestHybridRecord::TestConversion {
                    match_key: 67890,
                    value: 3,
                }, // NOT attributed
                TestHybridRecord::TestImpression {
                    match_key: 78901,
                    breakdown_key: 2,
                },
                TestHybridRecord::TestConversion {
                    match_key: 78901,
                    value: 4,
                }, // attributed twice, removed
                TestHybridRecord::TestConversion {
                    match_key: 78901,
                    value: 5,
                }, // attributed twice, removed
                TestHybridRecord::TestImpression {
                    match_key: 89012,
                    breakdown_key: 4,
                },
                TestHybridRecord::TestImpression {
                    match_key: 89012,
                    breakdown_key: 3,
                }, // duplicated impression with same match_key
                TestHybridRecord::TestConversion {
                    match_key: 89012,
                    value: 6,
                }, // removed
            ];

            // let expected = [[4, 1], [3, 2]];

            let world = TestWorld::<WithShards<2>>::with_shards(TestWorldConfig::default());

            let results: Vec<[Vec<AggregateableHybridReport<BA8, BA3>>; 3]> = world
                .malicious(records.clone().into_iter(), |ctx, input| {
                    let og_records = records.clone();
                    async move {
                        let indistinguishable_reports: Vec<
                            IndistinguishableHybridReport<BA8, BA3>,
                        > = input.iter().map(|r| r.clone().into()).collect::<Vec<_>>();

                        let prf_reports: Vec<PrfHybridReport<BA8, BA3>> = indistinguishable_reports
                            .iter()
                            .zip(og_records.iter())
                            .map(|(indist_report, test_report)| {
                                let match_key = match test_report {
                                    TestHybridRecord::TestConversion { match_key, .. }
                                    | TestHybridRecord::TestImpression { match_key, .. } => {
                                        match_key
                                    }
                                };
                                PrfHybridReport {
                                    match_key: *match_key,
                                    value: indist_report.value.clone(),
                                    breakdown_key: indist_report.breakdown_key.clone(),
                                }
                            })
                            .collect::<Vec<_>>();

                        aggregate_reports(ctx.clone(), prf_reports).await.unwrap()
                    }
                })
                .await;

            println!("results: {results:?}");
            // todo: reconstruct results
            // assert_eq!(results, expected);
        });
    }
}
