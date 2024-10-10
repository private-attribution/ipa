mod add;
mod generator;
mod input;
mod ipa;
mod multiply;

use core::fmt::Debug;
use std::{fs, path::Path, time::Duration};

pub use add::secure_add;
use comfy_table::{Cell, Color, Table};
use hyper::http::uri::Scheme;
pub use input::InputSource;
pub use multiply::secure_mul;
use tokio::time::sleep;

pub use self::ipa::{playbook_oprf_ipa, run_query_and_validate};
use crate::{
    config::{ClientConfig, NetworkConfig, PeerConfig},
    executor::IpaRuntime,
    ff::boolean_array::{BA20, BA3, BA8},
    helpers::query::DpMechanism,
    net::{ClientIdentity, MpcHelperClient},
    protocol::{dp::NoiseParams, ipa_prf::oprf_padding::insecure::OPRFPaddingDp},
};

pub type BreakdownKey = BA8;
pub type Timestamp = BA20;
pub type TriggerValue = BA3;

/// Validates that the expected result matches the actual.
///
/// ## Panics
/// If results don't match.
pub fn validate<'a, I, S>(expected: I, actual: I)
where
    I: IntoIterator<Item = &'a S>,
    I::IntoIter: ExactSizeIterator,
    S: PartialEq + Debug + 'a,
{
    let mut expected = expected.into_iter().fuse();
    let mut actual = actual.into_iter().fuse();
    let mut mismatch = Vec::new();

    let mut table = Table::new();
    table.set_header(vec!["Row", "Expected", "Actual", "Diff?"]);

    let mut i = 0;
    loop {
        let next_expected = expected.next();
        let next_actual = actual.next();

        if next_expected.is_none() && next_actual.is_none() {
            break;
        }

        let same = next_expected == next_actual; // with DP non-exact match here

        let color = if same { Color::Green } else { Color::Red };
        table.add_row(vec![
            Cell::new(format!("{i}")).fg(color),
            Cell::new(format!("{next_expected:?}")).fg(color),
            Cell::new(format!("{next_actual:?}")).fg(color),
            Cell::new(if same { "" } else { "X" }),
        ]);

        if !same {
            mismatch.push((i, next_expected, next_actual));
        }

        i += 1;
    }

    tracing::info!("\n{table}\n");

    assert!(
        mismatch.is_empty(),
        "Expected and actual results don't match: {mismatch:?}",
    );
}

/// Validates that the expected result matches the actual.
///
/// ## Panics
/// If results don't match.
pub fn validate_dp(
    expected: Vec<u32>,
    actual: Vec<u32>,
    epsilon: f64,
    per_user_credit_cap: u32,
    dp_mechanism: DpMechanism,
) {
    let mut expected = expected.into_iter().fuse();
    let mut actual = actual.into_iter().fuse();
    let mut mismatch = Vec::new();

    let mut table = Table::new();
    table.set_header(vec!["Row", "Expected", "Actual", "Diff?"]);

    let mut all_equal: bool = true;
    let mut i = 0;
    loop {
        let next_expected = expected.next();
        let next_actual = actual.next();

        if next_expected.is_none() && next_actual.is_none() {
            break;
        }

        // make sure DP noise actually changed at least one of the results
        if next_expected != next_actual {
            all_equal = false;
        }

        let next_expected_f64: f64 = next_expected.unwrap().into();
        let next_actual_f64: f64 = next_actual.unwrap().into();

        let noise_params = NoiseParams {
            epsilon,
            per_user_credit_cap,
            ell_1_sensitivity: per_user_credit_cap.into(),
            ell_2_sensitivity: per_user_credit_cap.into(),
            ell_infty_sensitivity: per_user_credit_cap.into(),
            dimensions: 256.0, // matches the hard coded number of breakdown keys in oprf_ipa.rs/execute
            ..Default::default()
        };
        let same = match dp_mechanism {
            DpMechanism::Binomial { epsilon: _ } => {
                let (mean, std) = crate::protocol::dp::binomial_noise_mean_std(&noise_params);
                next_actual_f64 - mean > next_expected_f64 - 10.0 * std
                    && next_actual_f64 - mean < next_expected_f64 + 10.0 * std
            }
            DpMechanism::DiscreteLaplace { epsilon: _ } => {
                let truncated_discrete_laplace = OPRFPaddingDp::new(
                    noise_params.epsilon,
                    noise_params.delta,
                    noise_params.per_user_credit_cap,
                )
                .unwrap();

                // This needs to be kept in sync with histogram values being BA32.
                // Here we are shifting the representation of negative noise values
                // from being large values close to 2^32 to being negative when we look
                // at them as floats.
                let next_actual_f64_shifted = if next_actual_f64 > 2.0_f64.powf(31.0) {
                    next_actual_f64 - 2.0_f64.powf(32.0)
                } else {
                    next_actual_f64
                };

                let (_, std) = truncated_discrete_laplace.mean_and_std();
                let tolerance_factor = 20.0; // set so this fails randomly with small probability
                                             // println!("mean = {mean}, std = {std}, tolerance_factor * std = {}",tolerance_factor * std);
                (next_actual_f64_shifted - next_expected_f64).abs() < tolerance_factor * 3.0 * std
            }
            DpMechanism::NoDp => next_expected == next_actual,
        };

        let color = if same { Color::Green } else { Color::Red };
        table.add_row(vec![
            Cell::new(format!("{i}")).fg(color),
            Cell::new(format!("{next_expected:?}")).fg(color),
            Cell::new(format!("{next_actual:?}")).fg(color),
            Cell::new(if same { "" } else { "X" }),
        ]);

        if !same {
            mismatch.push((i, next_expected, next_actual));
        }

        i += 1;
    }

    tracing::info!("\n{table}\n");

    assert!(
        mismatch.is_empty(),
        "Expected and actual results don't match: {mismatch:?}",
    );

    // make sure DP noise actually changed the results. For large epsilon and few breakdowns keys
    // we might end up not adding any noise
    if epsilon <= 1.0 {
        assert!(!all_equal,
                "Expected and actual results match exactly...probably DP noise is not being added when it should be");
    }
}

/// Creates 3 clients to talk to MPC helpers.
///
/// ## Panics
/// If configuration file `network_path` cannot be read from or if it does not conform to toml spec.
pub async fn make_clients(
    network_path: Option<&Path>,
    scheme: Scheme,
    wait: usize,
) -> ([MpcHelperClient; 3], NetworkConfig) {
    let mut wait = wait;
    let network = if let Some(path) = network_path {
        NetworkConfig::from_toml_str(&fs::read_to_string(path).unwrap()).unwrap()
    } else {
        NetworkConfig {
            peers: [
                PeerConfig::new("localhost:3000".parse().unwrap(), None),
                PeerConfig::new("localhost:3001".parse().unwrap(), None),
                PeerConfig::new("localhost:3002".parse().unwrap(), None),
            ],
            client: ClientConfig::default(),
        }
    };
    let network = network.override_scheme(&scheme);

    // Note: This closure is only called when the selected action uses clients.

    let clients =
        MpcHelperClient::from_conf(&IpaRuntime::current(), &network, &ClientIdentity::None);
    while wait > 0 && !clients_ready(&clients).await {
        tracing::debug!("waiting for servers to come up");
        sleep(Duration::from_secs(1)).await;
        wait -= 1;
    }
    (clients, network)
}

async fn clients_ready(clients: &[MpcHelperClient; 3]) -> bool {
    clients[0].echo("").await.is_ok()
        && clients[1].echo("").await.is_ok()
        && clients[2].echo("").await.is_ok()
}
