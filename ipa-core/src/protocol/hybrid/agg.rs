use std::collections::HashMap;

use crate::{
    error::Error,
    ff::{boolean::Boolean, boolean_array::BooleanArray, ArrayAccess},
    helpers::TotalRecords,
    protocol::{
        boolean::step::{EightBitStep, ThirtyTwoBitStep},
        context::{
            dzkp_validator::{DZKPValidator, TARGET_PROOF_SIZE},
            Context, DZKPUpgraded, MaliciousProtocolSteps, UpgradableContext,
        },
        hybrid::step::HybridStep,
        ipa_prf::boolean_ops::addition_sequential::integer_add,
        BooleanProtocols, RecordId,
    },
    report::hybrid::{AggregateableHybridReport, PrfHybridReport},
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
};

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
    let mut reports_by_matchkey = HashMap::new();
    reports_by_matchkey.reserve(reports.len() / 2);

    for report in reports {
        reports_by_matchkey
            .entry(report.match_key)
            .or_insert_with(Vec::new)
            .push(report);
    }

    // an honest client and report collector will only submit
    // one report with a breakdown key and one report with a value.
    // if there are less, it's unattributed. if more, something went wrong.
    // we remove these (instead of erroring/panicing).
    let report_pairs: Vec<[AggregateableHybridReport<BK, V>; 2]> = reports_by_matchkey
        .into_iter()
        .filter_map(|(_, value)| {
            if value.len() == 2 {
                Some([value[0].clone().into(), value[1].clone().into()])
            } else {
                None
            }
        })
        .collect::<Vec<_>>();

    let mut agg_reports = Vec::new();

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
        .set_total_records(TotalRecords::specified(2 * report_pairs.len())?);

    for (i, reports) in report_pairs.into_iter().enumerate() {
        let record_id_bk = RecordId::FIRST + 2 * i;
        let record_id_v = RecordId::FIRST + 2 * i + 1;
        let (breakdown_key, _) = integer_add::<_, EightBitStep, 1>(
            ctx.clone(),
            record_id_bk,
            &reports[0].breakdown_key.to_bits(),
            &reports[1].breakdown_key.to_bits(),
        )
        .await?;
        let (value, _) = integer_add::<_, ThirtyTwoBitStep, 1>(
            ctx.clone(),
            record_id_v,
            &reports[0].value.to_bits(),
            &reports[1].value.to_bits(),
        )
        .await?;

        agg_reports.push(AggregateableHybridReport::<BK, V> {
            match_key: (),
            breakdown_key: breakdown_key.collect_bits(),
            value: value.collect_bits(),
        });
    }

    Ok(agg_reports)
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
                    match_key: 34567,
                    breakdown_key: 1,
                },
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
                }, // attributed twice
                TestHybridRecord::TestConversion {
                    match_key: 78901,
                    value: 5,
                }, // attributed twice
                TestHybridRecord::TestImpression {
                    match_key: 89012,
                    breakdown_key: 4,
                },
                TestHybridRecord::TestConversion {
                    match_key: 89012,
                    value: 6,
                }, // attributed
                TestHybridRecord::TestConversion {
                    match_key: 90123,
                    value: 7,
                }, // NOT attributed
            ];

            // at this point, all unattributed values end up in index 0
            // we will zero them out later.
            // let expected = vec![
            //     22, 0, 43, // 14 + 8, 12 + 31
            //     13, 33, // 25 + 8
            //     0,
            // ];

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
                                    TestHybridRecord::TestConversion { match_key, .. } => match_key,
                                    TestHybridRecord::TestImpression { match_key, .. } => match_key,
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

            println!("{:?}", results);
            panic!();
        })
    }
}
