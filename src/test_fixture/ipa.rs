use super::TestWorld;
use crate::{
    ff::{GaloisField, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    ipa_test_input,
    protocol::{ipa::ipa, BreakdownKey, MatchKey},
    secret_sharing::{
        replicated::{malicious, malicious::ExtendableField, semi_honest},
        IntoShares,
    },
    test_fixture::{input::GenericReportTestInput, Reconstruct, Runner},
};
use rand::{
    distributions::{Distribution, Standard},
    Rng,
};
use std::cmp::min;

#[derive(Debug, Copy, Clone)]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum IpaSecurityModel {
    SemiHonest,
    Malicious,
}

#[derive(Debug, Clone)]
pub struct TestRawDataRecord {
    pub user_id: usize,
    pub timestamp: u32,
    pub is_trigger_report: bool,
    pub breakdown_key: u32,
    pub trigger_value: u32,
}

pub fn generate_random_user_records_in_reverse_chronological_order(
    rng: &mut impl Rng,
    max_records_per_user: usize,
    max_breakdown_key: u32,
    max_trigger_value: u32,
) -> Vec<TestRawDataRecord> {
    const MAX_USER_ID: usize = 1_000_000_000_000;
    const SECONDS_IN_EPOCH: u32 = 604_800;

    let random_user_id = rng.gen_range(0..MAX_USER_ID);
    let num_records_for_user = min(
        rng.gen_range(1..max_records_per_user),
        rng.gen_range(1..max_records_per_user),
    );
    let mut records_for_user = Vec::with_capacity(num_records_for_user);
    for _ in 0..num_records_for_user {
        let random_timestamp = rng.gen_range(0..SECONDS_IN_EPOCH);
        let is_trigger_report = rng.gen::<bool>();
        let random_breakdown_key = if is_trigger_report {
            0
        } else {
            rng.gen_range(0..max_breakdown_key)
        };
        let trigger_value = if is_trigger_report {
            rng.gen_range(1..max_trigger_value)
        } else {
            0
        };
        records_for_user.push(TestRawDataRecord {
            user_id: random_user_id,
            timestamp: random_timestamp,
            is_trigger_report,
            breakdown_key: random_breakdown_key,
            trigger_value,
        });
    }

    // sort in reverse time order
    records_for_user.sort_unstable_by(|a, b| b.timestamp.cmp(&a.timestamp));

    records_for_user
}

/// Assumes records all belong to the same user, and are in reverse chronological order
/// Will give incorrect results if this is not true
#[allow(clippy::missing_panics_doc)]
pub fn update_expected_output_for_user(
    records_for_user: &[TestRawDataRecord],
    expected_results: &mut [u32],
    per_user_cap: u32,
    attribution_window_seconds: u32,
) {
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
                if time_delta_to_source_report > attribution_window_seconds {
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
pub async fn test_ipa<F>(
    world: &TestWorld,
    records: &[TestRawDataRecord],
    expected_results: &[u32],
    config: IpaQueryConfig,
    security_model: IpaSecurityModel,
) where
    semi_honest::AdditiveShare<F>: Serializable,
    malicious::AdditiveShare<F>: Serializable,
    // todo: for semi-honest we don't need extendable fields.
    F: PrimeField + ExtendableField + IntoShares<semi_honest::AdditiveShare<F>>,
    Standard: Distribution<F>,
{
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
