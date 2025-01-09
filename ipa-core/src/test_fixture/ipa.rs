use std::{collections::HashMap, num::NonZeroU32};

use rand::{thread_rng, Rng};

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum IpaSecurityModel {
    SemiHonest,
    Malicious,
}

#[derive(Debug, Clone, Ord, PartialEq, PartialOrd, Eq)]
pub struct TestRawDataRecord {
    pub timestamp: u64,
    pub user_id: u64,
    pub is_trigger_report: bool,
    pub breakdown_key: u32,
    pub trigger_value: u32,
}

/// Insert `record` into `user_records`, maintaining timestamp order.
///
/// If there are existing records with the same timestamp, inserts the new record
/// randomly in any position that maintains timestamp order.
fn insert_sorted(user_records: &mut Vec<TestRawDataRecord>, record: TestRawDataRecord) {
    let upper = user_records.partition_point(|rec| rec.timestamp <= record.timestamp);
    if upper > 0 && user_records[upper - 1].timestamp == record.timestamp {
        let lower = user_records[0..upper - 1]
            .iter()
            .rposition(|rec| rec.timestamp < record.timestamp)
            .map_or(0, |lower| lower + 1);
        user_records.insert(thread_rng().gen_range(lower..=upper), record);
    } else {
        user_records.insert(upper, record);
    }
}

/// Executes IPA protocol in the clear, that is without any MPC helpers involved in the computation.
/// Useful to validate that MPC output makes sense by comparing the breakdowns produced by MPC IPA
/// with this function's results. Note that MPC version of IPA may apply DP noise to the aggregates,
/// so strict equality may not work.
///
/// Just like the MPC implementation, if the input contains records with duplicate timestamps, the
/// order those records are considered by the attribution algorithm is undefined, and the output
/// may be non-deterministic.
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
    // build a view that is convenient for attribution. match key -> events sorted by timestamp
    // that is more memory intensive, but should be faster to compute. We can always opt-out and
    // execute IPA in place
    let mut user_events = HashMap::new();
    for row in input {
        insert_sorted(
            user_events.entry(row.user_id).or_insert_with(Vec::new),
            row.clone(),
        );
    }

    let mut breakdowns = vec![0u32; usize::try_from(max_breakdown).unwrap()];
    for records_per_user in user_events.values() {
        let rev_records = records_per_user.iter().rev();
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

#[cfg(all(test, unit_test))]
mod tests {
    use super::*;

    fn insert_sorted_test<I: IntoIterator<Item = u64>>(iter: I) -> Vec<TestRawDataRecord> {
        fn test_record(timestamp: u64, breakdown_key: u32) -> TestRawDataRecord {
            TestRawDataRecord {
                timestamp,
                user_id: 0,
                is_trigger_report: false,
                breakdown_key,
                trigger_value: 0,
            }
        }

        let mut expected = Vec::new();
        let mut actual = Vec::new();
        for (i, v) in iter.into_iter().enumerate() {
            expected.push(v);
            super::insert_sorted(&mut actual, test_record(v, u32::try_from(i).unwrap()));
        }
        expected.sort_unstable();
        assert_eq!(
            expected,
            actual.iter().map(|rec| rec.timestamp).collect::<Vec<_>>()
        );

        actual
    }

    #[test]
    fn insert_sorted() {
        insert_sorted_test([1, 2, 3, 4]);
        insert_sorted_test([4, 3, 2, 1]);
        insert_sorted_test([2, 3, 1, 4]);

        let mut counts1 = [0, 0, 0];
        let mut counts5 = [0, 0, 0];
        let mut counts6 = [0, 0, 0];
        // The three twos (initially in positions 1, 5, and 6), should be placed in positions 2, 3,
        // and 4 in the output in random order. After 128 trials, each of these possibilities should
        // have occurred at least once.
        for _ in 0..128 {
            let result = insert_sorted_test([1, 2, 0, 3, 4, 2, 2]);

            let i1 = result.iter().position(|r| r.breakdown_key == 1).unwrap();
            counts1[i1 - 2] += 1;
            let i5 = result.iter().position(|r| r.breakdown_key == 5).unwrap();
            counts5[i5 - 2] += 1;
            let i6 = result.iter().position(|r| r.breakdown_key == 6).unwrap();
            counts6[i6 - 2] += 1;
        }
        for i in 0..3 {
            assert_ne!(counts1[i], 0);
            assert_ne!(counts5[i], 0);
            assert_ne!(counts6[i], 0);
        }

        let mut counts2 = [0, 0, 0];
        let mut counts5 = [0, 0, 0];
        let mut counts6 = [0, 0, 0];
        // The three zeros (initially in positions 2, 5, and 6), should be placed in positions 0, 1,
        // and 2 in the output in random order. After 128 trials, each of these possibilities should
        // have occurred at least once.
        for _ in 0..128 {
            let result = insert_sorted_test([1, 2, 0, 3, 4, 0, 0]);

            let i2 = result.iter().position(|r| r.breakdown_key == 2).unwrap();
            counts2[i2] += 1;
            let i5 = result.iter().position(|r| r.breakdown_key == 5).unwrap();
            counts5[i5] += 1;
            let i6 = result.iter().position(|r| r.breakdown_key == 6).unwrap();
            counts6[i6] += 1;
        }
        for i in 0..3 {
            assert_ne!(counts2[i], 0);
            assert_ne!(counts5[i], 0);
            assert_ne!(counts6[i], 0);
        }
    }
}
