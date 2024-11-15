use std::collections::BTreeMap;

use futures::{stream, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::{boolean::Boolean, boolean_array::BooleanArray, ArrayAccess},
    helpers::TotalRecords,
    protocol::{
        boolean::step::EightBitStep,
        context::{
            dzkp_validator::{validated_seq_join, DZKPValidator, TARGET_PROOF_SIZE},
            Context, DZKPUpgraded, MaliciousProtocolSteps, ShardedContext, UpgradableContext,
        },
        hybrid::step::{AggregateReportsStep, HybridStep},
        ipa_prf::boolean_ops::addition_sequential::integer_add,
        BooleanProtocols,
    },
    report::hybrid::{AggregateableHybridReport, PrfHybridReport},
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

enum MatchEntry<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    Empty,
    Single(AggregateableHybridReport<BK, V>),
    Pair(
        AggregateableHybridReport<BK, V>,
        AggregateableHybridReport<BK, V>,
    ),
    MoreThanTwo,
}

impl<BK, V> MatchEntry<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    pub fn add_report(&mut self, new_report: AggregateableHybridReport<BK, V>) {
        match self {
            Self::Empty => *self = Self::Single(new_report),
            Self::Single(old_report) => {
                *self = Self::Pair(old_report.clone(), new_report);
            }
            Self::Pair { .. } | Self::MoreThanTwo => *self = Self::MoreThanTwo,
        }
    }
}

/// This function takes in a vector of `PrfHybridReports`, groups them by the oprf of the `match_key`,
/// and collects all pairs of reports with the same `match_key` into a vector of paris (as an array.)
/// Note that any `match_key` which appears once or more than twice is removed.
/// An honest report collector will only provide a single impression report per `match_key` and
/// an honest client will only provide a single conversion report per `match_key`.
fn group_report_pairs<BK, V>(
    reports: Vec<PrfHybridReport<BK, V>>,
) -> Vec<[AggregateableHybridReport<BK, V>; 2]>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    let mut reports_by_matchkey: BTreeMap<u64, MatchEntry<BK, V>> = BTreeMap::new();

    for report in reports {
        let match_entry = reports_by_matchkey
            .entry(report.match_key)
            .or_insert(MatchEntry::Empty);
        match_entry.add_report(report.into());
    }

    // we only keep the reports from match_keys that provided exactly 2 reports
    reports_by_matchkey
        .into_values()
        .filter_map(|match_entry| match match_entry {
            MatchEntry::Pair(r1, r2) => Some([r1, r2]),
            _ => None,
        })
        .collect::<Vec<_>>()
}

/// This protocol is used to aggregate `PRFHybridReports` and returns `AggregateableHybridReports`.
/// It groups all the reports by the PRF of the `match_key`, finds all reports from `match_keys`
/// with that provided exactly 2 reports, then adds those 2 reports.
pub async fn aggregate_reports<BK, V, C>(
    ctx: C,
    reports: Vec<PrfHybridReport<BK, V>>,
) -> Result<Vec<AggregateableHybridReport<BK, V>>, Error>
where
    C: UpgradableContext + ShardedContext,
    BK: BooleanArray,
    V: BooleanArray,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
{
    let report_pairs = group_report_pairs(reports);

    let chunk_size: usize = TARGET_PROOF_SIZE / (BK::BITS as usize + V::BITS as usize);

    let ctx = ctx.set_total_records(TotalRecords::specified(report_pairs.len())?);

    let dzkp_validator = ctx.dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &HybridStep::GroupBySum,
            validate: &HybridStep::GroupBySumValidate,
        },
        chunk_size.next_power_of_two(),
    );

    let agg_ctx = dzkp_validator.context();

    let agg_work = stream::iter(report_pairs)
        .enumerate()
        .map(|(idx, reports)| {
            let agg_ctx = agg_ctx.clone();
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
                Ok::<_, Error>(AggregateableHybridReport::<BK, V> {
                    match_key: (),
                    breakdown_key: breakdown_key.collect_bits(),
                    value: value.collect_bits(),
                })
            }
        });

    validated_seq_join(dzkp_validator, agg_work)
        .try_collect()
        .await
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
        test_fixture::{
            hybrid::{TestAggregateableHybridReport, TestHybridRecord},
            Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards,
        },
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

            let expected = vec![
                TestAggregateableHybridReport {
                    match_key: (),
                    breakdown_key: 4,
                    value: 1,
                },
                TestAggregateableHybridReport {
                    match_key: (),
                    breakdown_key: 3,
                    value: 2,
                },
            ];

            let world = TestWorld::<WithShards<3>>::with_shards(TestWorldConfig::default());

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

            let results: Vec<TestAggregateableHybridReport> = results
                .into_iter()
                .map(|shard_result| {
                    shard_result[0]
                        .clone()
                        .into_iter()
                        .zip(shard_result[1].clone().into_iter())
                        .zip(shard_result[2].clone().into_iter())
                        .map(|((r1, r2), r3)| [&r1, &r2, &r3].reconstruct())
                        .collect::<Vec<_>>()
                })
                .flatten()
                .into_iter()
                .collect::<Vec<_>>();

            assert_eq!(results, expected);
        });
    }
}
