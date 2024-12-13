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
    utils::non_zero_prev_power_of_two,
};

enum MatchEntry<BK, V>
where
    BK: BooleanArray,
    V: BooleanArray,
{
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
            Self::Single(old_report) => {
                *self = Self::Pair(old_report.clone(), new_report);
            }
            Self::Pair { .. } | Self::MoreThanTwo => *self = Self::MoreThanTwo,
        }
    }

    pub fn into_pair(self) -> Option<[AggregateableHybridReport<BK, V>; 2]> {
        match self {
            Self::Pair(r1, r2) => Some([r1, r2]),
            _ => None,
        }
    }
}

/// This function takes in a vector of `PrfHybridReports`, groups them by the oprf of the `match_key`,
/// and collects all pairs of reports with the same `match_key` into a vector of paris (as an array.)
///
/// *Note*: Any `match_key` which appears once or more than twice is removed.
/// An honest report collector will only provide a single impression report per `match_key` and
/// an honest client will only provide a single conversion report per `match_key`.
/// Also note that a malicious client (intenional or bug) could provide exactly two conversions.
/// This would put the sum of conversion values into `breakdown_key` 0. As this is undetectable,
/// this makes `breakdown_key = 0` *unreliable*.
///
/// Note: Possible Perf opportunity by removing the `collect()`.
/// See [#1443](https://github.com/private-attribution/ipa/issues/1443).
///
/// *Note*: In order to add the pairs, the vector of pairs must be in the same order across all
/// three helpers. A standard `HashMap` uses system randomness for insertion placement, so we
/// use a `BTreeMap` to maintain consistent ordering across the helpers.
///
fn group_report_pairs_ordered<BK, V>(
    reports: Vec<PrfHybridReport<BK, V>>,
) -> Vec<[AggregateableHybridReport<BK, V>; 2]>
where
    BK: BooleanArray,
    V: BooleanArray,
{
    let mut reports_by_matchkey: BTreeMap<u64, MatchEntry<BK, V>> = BTreeMap::new();

    for report in reports {
        reports_by_matchkey
            .entry(report.match_key)
            .and_modify(|e| e.add_report(report.clone().into()))
            .or_insert(MatchEntry::Single(report.into()));
    }

    // we only keep the reports from match_keys that provided exactly 2 reports
    reports_by_matchkey
        .into_values()
        .filter_map(MatchEntry::into_pair)
        .collect::<Vec<_>>()
}

/// This protocol is used to aggregate `PRFHybridReports` and returns `AggregateableHybridReports`.
/// It groups all the reports by the PRF of the `match_key`, finds all reports from `match_keys`
/// with that provided exactly 2 reports, then adds those 2 reports.
/// TODO (Performance opportunity): These additions are not currently vectorized.
/// We are currently deferring that work until the protocol is complete.
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
    let report_pairs = group_report_pairs_ordered(reports);

    let chunk_size =
        non_zero_prev_power_of_two(TARGET_PROOF_SIZE / (BK::BITS as usize + V::BITS as usize));

    let ctx = ctx.set_total_records(TotalRecords::specified(report_pairs.len())?);

    let dzkp_validator = ctx.dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &HybridStep::GroupBySum,
            validate: &HybridStep::GroupBySumValidate,
        },
        chunk_size,
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

#[cfg(all(test, unit_test))]
pub mod test {
    use rand::Rng;

    use super::{aggregate_reports, group_report_pairs_ordered};
    use crate::{
        ff::{
            boolean_array::{BA3, BA8},
            U128Conversions,
        },
        helpers::Role,
        protocol::hybrid::step::AggregateReportsStep,
        report::hybrid::{
            AggregateableHybridReport, IndistinguishableHybridReport, PrfHybridReport,
        },
        secret_sharing::replicated::{
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
        sharding::{ShardConfiguration, ShardIndex},
        test_executor::{run, run_random},
        test_fixture::{
            hybrid::{TestAggregateableHybridReport, TestHybridRecord},
            Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards,
        },
    };

    // the inputs are laid out to work with exactly 2 shards
    // as if it we're resharded by match_key/prf
    const SHARDS: usize = 2;
    const SECOND_SHARD: ShardIndex = ShardIndex::from_u32(1);

    // we re-use these as the "prf" of the match_key
    // to avoid needing to actually do the prf here
    const SHARD1_MKS: [u64; 7] = [12345, 12345, 34567, 34567, 78901, 78901, 78901];
    const SHARD2_MKS: [u64; 7] = [23456, 23456, 45678, 56789, 67890, 67890, 67890];

    #[allow(clippy::too_many_lines)]
    fn get_records() -> Vec<TestHybridRecord> {
        let conversion_site_domain = "meta.com".to_string();
        let shard1_records = [
            TestHybridRecord::TestImpression {
                match_key: SHARD1_MKS[0],
                breakdown_key: 45,
                key_id: 0,
            },
            TestHybridRecord::TestConversion {
                match_key: SHARD1_MKS[1],
                value: 1,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 102,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestConversion {
                match_key: SHARD1_MKS[2],
                value: 3,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 103,
                epsilon: 0.0,
                sensitivity: 0.0,
            },
            TestHybridRecord::TestConversion {
                match_key: SHARD1_MKS[3],
                value: 4,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 104,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // not attibuted, but duplicated conversion. will land in breakdown_key 0
            TestHybridRecord::TestImpression {
                match_key: SHARD1_MKS[4],
                breakdown_key: 1,
                key_id: 0,
            }, // duplicated impression with same match_key
            TestHybridRecord::TestImpression {
                match_key: SHARD1_MKS[4],
                breakdown_key: 2,
                key_id: 0,
            }, // duplicated impression with same match_key
            TestHybridRecord::TestConversion {
                match_key: SHARD1_MKS[5],
                value: 7,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 105,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // removed
        ];
        let shard2_records = [
            TestHybridRecord::TestImpression {
                match_key: SHARD2_MKS[0],
                breakdown_key: 56,
                key_id: 0,
            },
            TestHybridRecord::TestConversion {
                match_key: SHARD2_MKS[1],
                value: 2,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 100,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed
            TestHybridRecord::TestImpression {
                match_key: SHARD2_MKS[2],
                breakdown_key: 78,
                key_id: 0,
            }, // NOT attributed
            TestHybridRecord::TestConversion {
                match_key: SHARD2_MKS[3],
                value: 5,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 101,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // NOT attributed
            TestHybridRecord::TestImpression {
                match_key: SHARD2_MKS[4],
                breakdown_key: 90,
                key_id: 0,
            }, // attributed twice, removed
            TestHybridRecord::TestConversion {
                match_key: SHARD2_MKS[5],
                value: 6,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 102,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed twice, removed
            TestHybridRecord::TestConversion {
                match_key: SHARD2_MKS[6],
                value: 7,
                key_id: 0,
                conversion_site_domain: conversion_site_domain.clone(),
                timestamp: 103,
                epsilon: 0.0,
                sensitivity: 0.0,
            }, // attributed twice, removed
        ];

        shard1_records
            .chunks(1)
            .zip(shard2_records.chunks(1))
            .flat_map(|(a, b)| a.iter().chain(b))
            .cloned()
            .collect()
    }

    #[test]
    fn group_reports_mpc() {
        run(|| async {
            let records = get_records();
            let expected = vec![
                [
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 0,
                        breakdown_key: 45,
                    },
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 1,
                        breakdown_key: 0,
                    },
                ],
                [
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 3,
                        breakdown_key: 0,
                    },
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 4,
                        breakdown_key: 0,
                    },
                ],
                [
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 0,
                        breakdown_key: 56,
                    },
                    TestAggregateableHybridReport {
                        match_key: (),
                        value: 2,
                        breakdown_key: 0,
                    },
                ],
            ];

            let world = TestWorld::<WithShards<SHARDS>>::with_shards(TestWorldConfig::default());
            #[allow(clippy::type_complexity)]
            let results: Vec<[Vec<[AggregateableHybridReport<BA8, BA3>; 2]>; 3]> = world
                .malicious(records.clone().into_iter(), |ctx, input| {
                    let match_keys = match ctx.shard_id() {
                        ShardIndex::FIRST => SHARD1_MKS,
                        SECOND_SHARD => SHARD2_MKS,
                        _ => panic!("invalid shard_id"),
                    };
                    async move {
                        let indistinguishable_reports: Vec<
                            IndistinguishableHybridReport<BA8, BA3>,
                        > = input.iter().map(|r| r.clone().into()).collect::<Vec<_>>();

                        let prf_reports: Vec<PrfHybridReport<BA8, BA3>> = indistinguishable_reports
                            .iter()
                            .zip(match_keys)
                            .map(|(indist_report, match_key)| PrfHybridReport {
                                match_key,
                                value: indist_report.value.clone(),
                                breakdown_key: indist_report.breakdown_key.clone(),
                            })
                            .collect::<Vec<_>>();
                        group_report_pairs_ordered(prf_reports)
                    }
                })
                .await;

            let results: Vec<[TestAggregateableHybridReport; 2]> = results
                .into_iter()
                .flat_map(|shard_result| {
                    shard_result[0]
                        .clone()
                        .into_iter()
                        .zip(shard_result[1].clone())
                        .zip(shard_result[2].clone())
                        .map(|((r1, r2), r3)| {
                            [
                                [&r1[0], &r2[0], &r3[0]].reconstruct(),
                                [&r1[1], &r2[1], &r3[1]].reconstruct(),
                            ]
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            assert_eq!(results, expected);
        });
    }

    #[test]
    fn aggregate_reports_test() {
        run(|| async {
            let records = get_records();
            let expected = vec![
                TestAggregateableHybridReport {
                    match_key: (),
                    value: 1,
                    breakdown_key: 45,
                },
                TestAggregateableHybridReport {
                    match_key: (),
                    value: 7,
                    breakdown_key: 0,
                },
                TestAggregateableHybridReport {
                    match_key: (),
                    value: 2,
                    breakdown_key: 56,
                },
            ];

            let world = TestWorld::<WithShards<SHARDS>>::with_shards(TestWorldConfig::default());

            let results: Vec<[Vec<AggregateableHybridReport<BA8, BA3>>; 3]> = world
                .malicious(records.clone().into_iter(), |ctx, input| {
                    let match_keys = match ctx.shard_id() {
                        ShardIndex::FIRST => SHARD1_MKS,
                        SECOND_SHARD => SHARD2_MKS,
                        _ => panic!("invalid shard_id"),
                    };
                    async move {
                        let indistinguishable_reports: Vec<
                            IndistinguishableHybridReport<BA8, BA3>,
                        > = input.iter().map(|r| r.clone().into()).collect::<Vec<_>>();

                        let prf_reports: Vec<PrfHybridReport<BA8, BA3>> = indistinguishable_reports
                            .iter()
                            .zip(match_keys)
                            .map(|(indist_report, match_key)| PrfHybridReport {
                                match_key,
                                value: indist_report.value.clone(),
                                breakdown_key: indist_report.breakdown_key.clone(),
                            })
                            .collect::<Vec<_>>();

                        aggregate_reports(ctx.clone(), prf_reports).await.unwrap()
                    }
                })
                .await;

            let results: Vec<TestAggregateableHybridReport> = results
                .into_iter()
                .flat_map(|shard_result| {
                    shard_result[0]
                        .clone()
                        .into_iter()
                        .zip(shard_result[1].clone())
                        .zip(shard_result[2].clone())
                        .map(|((r1, r2), r3)| [&r1, &r2, &r3].reconstruct())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();

            assert_eq!(results, expected);
        });
    }

    fn build_prf_hybrid_report(
        match_key: u64,
        value: u8,
        breakdown_key: u8,
    ) -> PrfHybridReport<BA8, BA3> {
        PrfHybridReport::<BA8, BA3> {
            match_key,
            value: Replicated::new(BA3::truncate_from(value), BA3::truncate_from(0_u128)),
            breakdown_key: Replicated::new(
                BA8::truncate_from(breakdown_key),
                BA8::truncate_from(0_u128),
            ),
        }
    }

    fn build_aggregateable_report(
        value: u8,
        breakdown_key: u8,
    ) -> AggregateableHybridReport<BA8, BA3> {
        AggregateableHybridReport::<BA8, BA3> {
            match_key: (),
            value: Replicated::new(BA3::truncate_from(value), BA3::truncate_from(0_u128)),
            breakdown_key: Replicated::new(
                BA8::truncate_from(breakdown_key),
                BA8::truncate_from(0_u128),
            ),
        }
    }

    #[test]
    fn group_reports() {
        let reports = vec![
            build_prf_hybrid_report(42, 2, 0),  // pair: index (1,0)
            build_prf_hybrid_report(42, 0, 3),  // pair: index (1,1)
            build_prf_hybrid_report(17, 4, 0),  // pair: index (0,0)
            build_prf_hybrid_report(17, 0, 13), // pair: index (0,1)
            build_prf_hybrid_report(13, 0, 5),  // single
            build_prf_hybrid_report(11, 2, 0),  // single
            build_prf_hybrid_report(31, 1, 2),  // triple
            build_prf_hybrid_report(31, 3, 4),  // triple
            build_prf_hybrid_report(31, 5, 6),  // triple
        ];

        let expected = vec![
            [
                build_aggregateable_report(4, 0),
                build_aggregateable_report(0, 13),
            ],
            [
                build_aggregateable_report(2, 0),
                build_aggregateable_report(0, 3),
            ],
        ];

        let results = group_report_pairs_ordered(reports);
        assert_eq!(results, expected);
    }

    /// This test checks that the sharded malicious `aggregate_reports` fails
    /// under a simple bit flip attack by H1.
    #[test]
    #[should_panic(expected = "DZKPValidationFailed")]
    fn sharded_fail_under_bit_flip_attack_on_breakdown_key() {
        use crate::helpers::in_memory_config::MaliciousHelper;
        run_random(|mut rng| async move {
            let target_shard = ShardIndex::from(rng.gen_range(0..u32::try_from(SHARDS).unwrap()));
            let mut config = TestWorldConfig::default();

            let step = format!("{}/{}", AggregateReportsStep::AddBK.as_ref(), "bit0",);
            config.stream_interceptor =
                MaliciousHelper::new(Role::H2, config.role_assignment(), move |ctx, data| {
                    // flip a bit of the match_key on the target shard, H1
                    if ctx.gate.as_ref().contains(&step)
                        && ctx.dest == Role::H1
                        && ctx.shard == Some(target_shard)
                    {
                        data[0] ^= 1u8;
                    }
                });

            let world = TestWorld::<WithShards<SHARDS>>::with_shards(config);
            let records = get_records();
            let _results: Vec<[Vec<AggregateableHybridReport<BA8, BA3>>; 3]> = world
                .malicious(records.clone().into_iter(), |ctx, input| {
                    let match_keys = match ctx.shard_id() {
                        ShardIndex::FIRST => SHARD1_MKS,
                        SECOND_SHARD => SHARD2_MKS,
                        _ => panic!("invalid shard_id"),
                    };
                    async move {
                        let indistinguishable_reports: Vec<
                            IndistinguishableHybridReport<BA8, BA3>,
                        > = input.iter().map(|r| r.clone().into()).collect::<Vec<_>>();

                        let prf_reports: Vec<PrfHybridReport<BA8, BA3>> = indistinguishable_reports
                            .iter()
                            .zip(match_keys)
                            .map(|(indist_report, match_key)| PrfHybridReport {
                                match_key,
                                value: indist_report.value.clone(),
                                breakdown_key: indist_report.breakdown_key.clone(),
                            })
                            .collect::<Vec<_>>();

                        aggregate_reports(ctx.clone(), prf_reports).await.unwrap()
                    }
                })
                .await;
        });
    }
}
