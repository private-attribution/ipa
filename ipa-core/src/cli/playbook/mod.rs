mod input;
mod ipa;
mod multiply;

use core::fmt::Debug;
use std::{fs, path::Path, time::Duration};

use comfy_table::{Cell, Color, Table};
use hyper::http::uri::Scheme;
pub use input::InputSource;
pub use multiply::secure_mul;
use tokio::time::sleep;

pub use self::ipa::playbook_oprf_ipa;
use crate::{
    config::{ClientConfig, NetworkConfig, PeerConfig},
    net::{ClientIdentity, MpcHelperClient},
};

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

        let same = next_expected == next_actual;
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

    let clients = MpcHelperClient::from_conf(&network, &ClientIdentity::None);
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
