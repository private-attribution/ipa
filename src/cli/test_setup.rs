use crate::{
    cli::{keygen, KeygenArgs},
    config::{ClientConfig, HpkeClientConfig, NetworkConfig, PeerConfig},
};
use clap::Args;
use std::{
    error::Error,
    fs::{self, DirBuilder},
    iter::zip,
    path::PathBuf,
};
use toml::{map::Map, Table, Value};

#[derive(Debug, Args)]
#[clap(
    name = "test_setup",
    about = "Prepare a test network of three helpers",
    next_help_heading = "Test Setup Options"
)]
pub struct TestSetupArgs {
    #[arg(short, long, default_value = "test_data")]
    output_dir: PathBuf,

    /// Ignored. The same configuration can be used for HTTP and HTTPS.
    #[arg(long)]
    disable_https: bool,

    /// Configure helper clients to use HTTP1 instead of default HTTP version (HTTP2 at the moment).
    #[arg(long, default_value_t = false)]
    use_http1: bool,

    #[arg(short, long, num_args = 3, value_name = "PORT", default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,
}

/// Prepare a test network of three helpers.
///
/// # Errors
/// If a problem is encountered.
///
/// # Panics
/// If something that shouldn't happen goes wrong.
pub fn test_setup(args: TestSetupArgs) -> Result<(), Box<dyn Error>> {
    if args.output_dir.exists() {
        if !args.output_dir.is_dir() || args.output_dir.read_dir()?.next().is_some() {
            return Err("output directory already exists and is not empty".into());
        }
    } else {
        DirBuilder::new().create(&args.output_dir)?;
    }

    let peers = zip([1, 2, 3], args.ports)
        .map(|(id, port)| {
            let keygen_args = KeygenArgs {
                name: String::from("localhost"),
                tls_cert: args.output_dir.join(format!("h{id}.pem")),
                tls_key: args.output_dir.join(format!("h{id}.key")),
                mk_public_key: args.output_dir.join(format!("h{id}_mk.pub")),
                mk_private_key: args.output_dir.join(format!("h{id}_mk")),
            };

            keygen(&keygen_args)?;

            let certificate = fs::read_to_string(&keygen_args.tls_cert)?;
            let mk_public_key = fs::read_to_string(&keygen_args.mk_public_key)?;

            // Constructing toml directly because it avoids linking
            // a PEM library to serialize the certificate.
            let mut peer = Map::new();
            peer.insert(
                String::from("url"),
                Value::String(format!("localhost:{port}")),
            );
            peer.insert(String::from("certificate"), Value::String(certificate));
            peer.insert(
                String::from("hpke"),
                Value::Table(encode_hpke(mk_public_key)),
            );

            Ok::<_, Box<dyn Error>>(peer.into())
        })
        .collect::<Result<Vec<Value>, _>>()?
        .into();

    let client_config = if args.use_http1 {
        ClientConfig::use_http1()
    } else {
        ClientConfig::default()
    };
    let mut network_config = Map::new();
    network_config.insert(String::from("peers"), peers);
    network_config.insert(
        String::from("client"),
        Table::try_from(client_config)?.into(),
    );
    let config_str = toml::to_string_pretty(&network_config)?;

    // make sure network config is valid
    if cfg!(debug_assertions) {
        assert_network_config(&network_config, &config_str);
    }

    fs::write(args.output_dir.join("network.toml"), config_str)?;

    Ok(())
}

/// Creates a section in TOML that describes the HPKE configuration for match key encryption.
fn encode_hpke(public_key: String) -> Table {
    let mut hpke_table = Table::new();
    // TODO: key registry requires a set of public keys with their "identifier". Right now
    // we encode only one key
    hpke_table.insert(String::from("public_key"), Value::String(public_key));

    hpke_table
}

/// Validates that the resulting [`NetworkConfig`] can be read by helper binary correctly, i.e.
/// all the values get serialized.
///
/// [`NetworkConfig`]: NetworkConfig
fn assert_network_config(config_toml: &Map<String, Value>, config_str: &str) {
    let nw_config =
        NetworkConfig::from_toml_str(config_str).expect("Can deserialize network config");

    let Value::Array(peer_config_expected) = config_toml.get("peers").expect("peer section must be present") else {
        panic!("peers section in toml config is not a table");
    };
    for (i, peer_config_actual) in nw_config.peers.iter().enumerate() {
        assert_peer_config(&peer_config_expected[i], peer_config_actual);
    }
}

/// Validates that the resulting [`PeerConfig`] can be read by helper binary correctly.
///
/// [`PeerConfig`]: PeerConfig
fn assert_peer_config(expected: &Value, actual: &PeerConfig) {
    assert_eq!(
        expected.get("url").unwrap().as_str(),
        Some(actual.url.to_string()).as_deref()
    );

    assert_hpke_config(
        expected.get("hpke").expect("hpke section must be present"),
        actual.hpke_config.as_ref(),
    );
}

/// Validates that the resulting [`HpkeClientConfig`] can be read by helper binary correctly.
///
/// [`HpkeClientConfig`]: HpkeClientConfig
fn assert_hpke_config(expected: &Value, actual: Option<&HpkeClientConfig>) {
    assert_eq!(
        expected
            .get("public_key")
            .and_then(toml::Value::as_str)
            .map(ToOwned::to_owned),
        actual.map(|v| v.public_key.clone())
    );
}
