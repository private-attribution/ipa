use std::{collections::HashMap, num::NonZeroU32, ops::Deref};

use crate::protocol::ipa_prf::prf_sharding::GroupingKey;
#[cfg(feature = "in-memory-infra")]
use crate::{
    ff::{PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    ipa_test_input,
    protocol::{ipa::ipa, BreakdownKey, MatchKey, Timestamp, TriggerValue},
    report::OprfReport,
    secret_sharing::{
        replicated::{
            malicious, malicious::ExtendableField, semi_honest,
            semi_honest::AdditiveShare as Replicated,
        },
        IntoShares,
    },
    test_fixture::{input::GenericReportTestInput, Reconstruct},
};

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum IpaSecurityModel {
    SemiHonest,
    Malicious,
}

pub enum IpaQueryStyle {
    SortInMpc,
    Oprf,
}

#[derive(Debug, Clone)]
pub struct TestRawDataRecord {
    pub timestamp: u64,
    pub user_id: u64,
    pub is_trigger_report: bool,
    pub breakdown_key: u32,
    pub trigger_value: u32,
}

impl GroupingKey for TestRawDataRecord {
    fn get_grouping_key(&self) -> u64 {
        self.user_id
    }
}

/// Executes IPA protocol in the clear, that is without any MPC helpers involved in the computation.
/// Useful to validate that MPC output makes sense by comparing the breakdowns produced by MPC IPA
/// with this function's results. Note that MPC version of IPA may apply DP noise to the aggregates,
/// so strict equality may not work.
///
/// This function requires input to be sorted by the timestamp and returns a vector of contributions
/// sorted by the breakdown key.
///
/// ## Panics
/// Will panic if you run in on Intel 80286 or any other 16 bit hardware.
pub fn ipa_in_the_clear(
    input: &[TestRawDataRecord],
    per_user_cap: u32,
    attribution_window: Option<NonZeroU32>,
    max_breakdown: u32,
    order: &CappingOrder,
) -> Vec<u32> {
    // build a view that is convenient for attribution. match key -> events sorted by timestamp in reverse
    // that is more memory intensive, but should be faster to compute. We can always opt-out and
    // execute IPA in place
    let mut user_events = HashMap::new();
    let mut last_ts = 0;
    for row in input {
        if cfg!(debug_assertions) {
            assert!(
                last_ts <= row.timestamp,
                "Input is not sorted: last row had timestamp {last_ts} that is greater than \
                  {this_ts} timestamp of the current row",
                this_ts = row.timestamp
            );
            last_ts = row.timestamp;
        }

        user_events
            .entry(row.user_id)
            .or_insert_with(Vec::new)
            .push(row);
    }

    let mut breakdowns = vec![0u32; usize::try_from(max_breakdown).unwrap()];
    for records_per_user in user_events.values() {
        // it works because input is sorted and vectors preserve the insertion order
        // so records in `rev` are returned in reverse chronological order
        let rev_records = records_per_user.iter().rev().map(Deref::deref);
        update_expected_output_for_user(
            rev_records,
            &mut breakdowns,
            per_user_cap,
            attribution_window,
            order,
        );
    }

    breakdowns
}

pub enum CappingOrder {
    CapOldestFirst,
    CapMostRecentFirst,
}

/// Assumes records all belong to the same user, and are in reverse chronological order
/// Will give incorrect results if this is not true
#[allow(clippy::missing_panics_doc)]
fn update_expected_output_for_user<'a, I: IntoIterator<Item = &'a TestRawDataRecord>>(
    records_for_user: I,
    expected_results: &mut [u32],
    per_user_cap: u32,
    attribution_window_seconds: Option<NonZeroU32>,
    order: &CappingOrder,
) {
    let within_window = |value: u64| -> bool {
        if let Some(window) = attribution_window_seconds {
            value <= u64::from(window.get())
        } else {
            // if window is not specified, it is considered of infinite size. Everything is
            // within that window.
            true
        }
    };

    let mut attributed_triggers = Vec::new();
    let mut pending_trigger_reports = Vec::new();
    for record in records_for_user {
        if record.is_trigger_report {
            pending_trigger_reports.push(record);
        } else if !pending_trigger_reports.is_empty() {
            for trigger_report in pending_trigger_reports {
                let time_delta_to_source_report = trigger_report.timestamp - record.timestamp;

                // only count trigger reports that are within the attribution window
                // only if attribution_window is set. This matches the behaviour in MPC
                if !within_window(time_delta_to_source_report) {
                    continue;
                }

                attributed_triggers.push((trigger_report, record));
            }
            pending_trigger_reports = Vec::new();
        }
    }

    match order {
        CappingOrder::CapOldestFirst => {
            update_breakdowns(attributed_triggers, expected_results, per_user_cap);
        }
        CappingOrder::CapMostRecentFirst => update_breakdowns(
            attributed_triggers.into_iter().rev(),
            expected_results,
            per_user_cap,
        ),
    }
}

fn update_breakdowns<'a, I>(attributed_triggers: I, expected_results: &mut [u32], per_user_cap: u32)
where
    I: IntoIterator<Item = (&'a TestRawDataRecord, &'a TestRawDataRecord)>,
{
    let mut total_contribution = 0;
    for (trigger_report, source_report) in attributed_triggers {
        let delta_to_per_user_cap = per_user_cap - total_contribution;
        let capped_contribution =
            std::cmp::min(delta_to_per_user_cap, trigger_report.trigger_value);
        let bk: usize = source_report.breakdown_key.try_into().unwrap();
        expected_results[bk] += capped_contribution;
        total_contribution += capped_contribution;
    }
}

/// # Panics
/// If any of the IPA protocol modules panic
#[cfg(feature = "in-memory-infra")]
pub async fn test_ipa<F>(
    world: &super::TestWorld,
    records: &[TestRawDataRecord],
    expected_results: &[u32],
    config: IpaQueryConfig,
    security_model: IpaSecurityModel,
) where
    semi_honest::AdditiveShare<F>: Serializable,
    malicious::AdditiveShare<F>: Serializable,
    // todo: for semi-honest we don't need extendable fields.
    F: PrimeField + ExtendableField + IntoShares<semi_honest::AdditiveShare<F>>,
    rand::distributions::Standard: rand::distributions::Distribution<F>,
{
    use super::Runner;

    let records = records
        .iter()
        .map(|x| {
            ipa_test_input!(
                {
                    timestamp: x.timestamp,
                    match_key: x.user_id,
                    is_trigger_report: x.is_trigger_report,
                    breakdown_key: x.breakdown_key,
                    trigger_value: x.trigger_value,
                };
                (F, MatchKey, BreakdownKey)
            )
        })
        .collect::<Vec<_>>();

    let result: Vec<F> = match security_model {
        IpaSecurityModel::Malicious => world
            .malicious(records.into_iter(), |ctx, input_rows| async move {
                ipa::<_, _, _, F, MatchKey, BreakdownKey>(ctx, &input_rows, config)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct(),
        IpaSecurityModel::SemiHonest => world
            .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                ipa::<_, _, _, F, MatchKey, BreakdownKey>(ctx, &input_rows, config)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct(),
    };
    let result = result
        .into_iter()
        .map(|v| u32::try_from(v.as_u128()).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(result, expected_results);
}

/// # Panics
/// If any of the IPA protocol modules panic
#[cfg(feature = "in-memory-infra")]
pub async fn test_oprf_ipa<F>(
    world: &super::TestWorld,
    mut records: Vec<TestRawDataRecord>,
    expected_results: &[u32],
    config: IpaQueryConfig,
) where
    F: PrimeField + ExtendableField + IntoShares<semi_honest::AdditiveShare<F>>,
    rand::distributions::Standard: rand::distributions::Distribution<F>,
    semi_honest::AdditiveShare<F>: Serializable,
{
    use crate::{
        ff::{Field, Gf2},
        protocol::{
            basics::ShareKnownValue,
            ipa_prf::prf_sharding::{
                attribution_and_capping_and_aggregation, compute_histogram_of_users_with_row_count,
                PrfShardedIpaInputRow,
            },
        },
        report::EventType,
        secret_sharing::SharedValue,
        test_fixture::Runner,
    };

    let user_cap: i32 = config.per_user_credit_cap.try_into().unwrap();
    assert!(
        user_cap & (user_cap - 1) == 0,
        "This code only works for a user cap which is a power of 2"
    );

    //TODO(richaj) This manual sorting will be removed once we have the PRF sharding in place
    records.sort_by(|a, b| b.user_id.cmp(&a.user_id));

    let histogram = compute_histogram_of_users_with_row_count(&records);
    let ref_to_histogram = &histogram;

    let result: Vec<F> = world
        .semi_honest(
            records.into_iter(),
            |ctx, input_rows: Vec<OprfReport<BreakdownKey, TriggerValue, Timestamp>>| async move {
                let sharded_input = input_rows
                    .into_iter()
                    .map(|single_row| {
                        let is_trigger_bit_share = if single_row.event_type == EventType::Trigger {
                            Replicated::share_known_value(&ctx, Gf2::ONE)
                        } else {
                            Replicated::share_known_value(&ctx, Gf2::ZERO)
                        };
                        PrfShardedIpaInputRow {
                            prf_of_match_key: single_row.mk_oprf,
                            is_trigger_bit: is_trigger_bit_share,
                            breakdown_key: single_row.breakdown_key,
                            trigger_value: single_row.trigger_value,
                            timestamp: single_row.timestamp,
                        }
                    })
                    .collect::<Vec<_>>();

                attribution_and_capping_and_aggregation::<
                    _,
                    BreakdownKey,
                    TriggerValue,
                    Timestamp,
                    Replicated<F>,
                    F,
                >(
                    ctx,
                    sharded_input,
                    user_cap.ilog2().try_into().unwrap(),
                    config.attribution_window_seconds,
                    ref_to_histogram,
                )
                .await
                .unwrap()
            },
        )
        .await
        .reconstruct();

    let mut result = result
        .into_iter()
        .map(|v| u32::try_from(v.as_u128()).unwrap())
        .collect::<Vec<_>>();

    //TODO(richaj): To be removed once the function supports non power of 2 breakdowns
    let _ = result.split_off(expected_results.len());
    assert_eq!(result, expected_results);
}
