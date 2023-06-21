use std::{collections::HashMap, num::NonZeroU32, ops::Deref};

#[cfg(feature = "in-memory-infra")]
use crate::{
    ff::{GaloisField, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    ipa_test_input,
    protocol::{ipa::ipa, BreakdownKey, MatchKey},
    secret_sharing::{
        replicated::{malicious, malicious::ExtendableField, semi_honest},
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

#[derive(Debug, Clone)]
pub struct TestRawDataRecord {
    pub timestamp: u64,
    pub user_id: u64,
    pub is_trigger_report: bool,
    pub breakdown_key: u32,
    pub trigger_value: u32,
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
) -> Vec<u32> {
    // build a view that is convenient for attribution. match key -> events sorted by timestamp in reverse
    // that is more memory intensive, but should be faster to compute. We can always opt-out and
    // execute IPA in place
    let mut user_events = HashMap::new();
    let (mut max_breakdown, mut last_ts) = (0, 0);
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
        max_breakdown = max_breakdown.max(row.breakdown_key);
    }

    let mut breakdowns = vec![0u32; usize::try_from(max_breakdown + 1).unwrap()];
    for records_per_user in user_events.values() {
        // it works because input is sorted and vectors preserve the insertion order
        // so records in `rev` are returned in reverse chronological order
        let rev_records = records_per_user.iter().rev().map(Deref::deref);
        update_expected_output_for_user(
            rev_records,
            &mut breakdowns,
            per_user_cap,
            attribution_window,
        );
    }

    breakdowns
}

/// Assumes records all belong to the same user, and are in reverse chronological order
/// Will give incorrect results if this is not true
#[allow(clippy::missing_panics_doc)]
fn update_expected_output_for_user<'a, I: IntoIterator<Item = &'a TestRawDataRecord>>(
    records_for_user: I,
    expected_results: &mut [u32],
    per_user_cap: u32,
    attribution_window_seconds: Option<NonZeroU32>,
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

    let mut pending_trigger_reports = Vec::new();
    let mut total_contribution = 0;
    for record in records_for_user {
        if total_contribution >= per_user_cap {
            break;
        }

        if record.is_trigger_report {
            pending_trigger_reports.push(record);
        } else if !pending_trigger_reports.is_empty() {
            for trigger_report in &pending_trigger_reports {
                let time_delta_to_source_report = trigger_report.timestamp - record.timestamp;

                // only count trigger reports that are within the attribution window
                // only if attribution_window is set. This matches the behaviour in MPC
                if !within_window(time_delta_to_source_report) {
                    continue;
                }

                let delta_to_per_user_cap = per_user_cap - total_contribution;
                let capped_contribution =
                    std::cmp::min(delta_to_per_user_cap, trigger_report.trigger_value);
                let bk: usize = record.breakdown_key.try_into().unwrap();
                expected_results[bk] += capped_contribution;
                total_contribution += capped_contribution;
            }
            pending_trigger_reports.clear();
        }
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

    let result: Vec<GenericReportTestInput<F, MatchKey, BreakdownKey>> = match security_model {
        IpaSecurityModel::Malicious => world
            .malicious(records, |ctx, input_rows| async move {
                ipa::<_, _, _, F, MatchKey, BreakdownKey>(ctx, &input_rows, config)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct(),
        IpaSecurityModel::SemiHonest => world
            .semi_honest(records, |ctx, input_rows| async move {
                ipa::<_, _, _, F, MatchKey, BreakdownKey>(ctx, &input_rows, config)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct(),
    };

    assert_eq!(
        config.max_breakdown_key,
        u32::try_from(result.len()).unwrap()
    );

    for (i, expected) in expected_results.iter().enumerate() {
        assert_eq!(
            [i as u128, u128::from(*expected)],
            [
                result[i].breakdown_key.as_u128(),
                result[i].trigger_value.as_u128()
            ]
        );
    }
}
