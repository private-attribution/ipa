use std::error::Error;
use std::fs;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};
use clap::Args;
use config::Map;
use toml::{Table, Value};
use crate::config::{ClientConfig, HpkeClientConfig, NetworkConfig, PeerConfig};
use crate::helpers::HelperIdentity;

#[derive(Debug, Args)]
#[clap(name = "conf-gen", about = "Generate client config for 3 MPC helper parties")]
pub struct ConfGenArgs {
    #[arg(long, visible_alias = "h1")]
    pub(crate) h1_url: String,
    #[arg(long, visible_alias = "h2")]
    pub(crate) h2_url: String,
    #[arg(long, visible_alias = "h3")]
    pub(crate) h3_url: String,

    /// Path to the folder where certificates and public keys are stored. It must have all 3 helper's
    /// public keys and TLS certificates. Additionally DNS names on the certificates must match
    /// `h1_name`,..,`h3_name` values provided for this command, otherwise configuration won't work.
    #[arg(long)]
    pub(crate) keys_folder: PathBuf,

    /// Destination folder for the config file. If not specified, `keys_folder` will be used.
    #[arg(long)]
    pub(crate) out_folder: Option<PathBuf>,

    /// Overwrite configuration file if it exists at destination.
    #[arg(long)]
    pub(crate) overwrite: bool,
}


pub fn setup(args: ConfGenArgs) -> Result<(), Box<dyn Error>> {
    // let peers = [
    //     peer_config(HelperIdentity::ONE, &args.keys_folder),
    //     peer_config(HelperIdentity::TWO, &args.keys_folder),
    //     peer_config(HelperIdentity::THREE, &args.keys_folder),
    // ];
    //
    // let network_config = NetworkConfig::new(peers, ClientConfig::use_http2());
    // let out_folder = args.out_folder.unwrap_or(args.keys_folder);
    // let mut conf_file = File::options().write(true)
    //     .create_new(!args.overwrite)
    //     .truncate(args.overwrite)
    //     .open(out_folder.join("network.toml"))?;
    // conf_file.write(toml::to_string_pretty(&network_config)?.as_bytes())?;
    // Ok(())
    todo!()
}

pub struct HelperClientConf<'a> {
    host: &'a str,
    port: u16,
    tls_cert_file: &'a Path,
    mk_public_key_file: &'a Path
}

/// Generates client configuration file at the destination requested.
pub fn gen_client_config<'a>(
    clients_conf: [HelperClientConf<'a>; 3],
    use_http1: bool,
    conf_file_name: &Path
) -> Result<(), Box<dyn Error>> {

    conf_file_name.is_file().then_some(()).ok_or_else(|| format!("{} is not a file", conf_file_name.display()))?;

    let mut peers = Vec::<Value>::with_capacity(3);
    for client_conf in clients_conf {
        let certificate = fs::read_to_string(&client_conf.tls_cert_file)?;
        let mk_public_key = fs::read_to_string(&client_conf.mk_public_key_file)?;

        // Constructing toml directly because it avoids linking
        // a PEM library to serialize the certificate.
        let mut peer = Map::new();
        peer.insert(
            String::from("url"),
            Value::String(format!("{host}:{port}", host = client_conf.host, port = client_conf.port)),
        );
        peer.insert(String::from("certificate"), Value::String(certificate));
        peer.insert(
            String::from("hpke"),
            Value::Table(encode_hpke(mk_public_key)),
        );
        peers.push(peer.into())
    }

    let client_config = if use_http1 {
        ClientConfig::use_http1()
    } else {
        ClientConfig::default()
    };
    let mut network_config = Map::new();
    network_config.insert(String::from("peers"), peers.into());
    network_config.insert(
        String::from("client"),
        Table::try_from(client_config)?.into(),
    );
    let config_str = toml::to_string_pretty(&network_config)?;

    // make sure network config is valid
    if cfg!(debug_assertions) {
        assert_network_config(&network_config, &config_str);
    }

    fs::write(conf_file_name, config_str)?;

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
