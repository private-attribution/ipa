use std::{fs, fs::File, io::Write, iter::zip, path::PathBuf};

use clap::Args;
use config::Map;
use hpke::Serializable as _;
use toml::{Table, Value};

use crate::{
    cli::paths::PathExt,
    config::{ClientConfig, HpkeClientConfig, NetworkConfig, PeerConfig},
    error::BoxError,
};

#[derive(Debug, Args)]
#[clap(about = "Generate client config for 3 MPC helper parties")]
pub struct ConfGenArgs {
    #[arg(short, long, num_args = 3, value_name = "PORT", default_values = vec!["3000", "3001", "3002"])]
    ports: Vec<u16>,

    #[arg(long, num_args = 3, default_values = vec!["localhost", "localhost", "localhost"])]
    hosts: Vec<String>,

    /// Path to the folder where certificates and public keys are stored. It must have all 3 helper's
    /// public keys and TLS certificates named according to the naming [`convention`].
    ///
    /// [`convention`]: crate::cli::CliPaths
    #[arg(long)]
    pub(crate) keys_dir: PathBuf,

    /// Destination folder for the config file. If not specified, `keys_folder` will be used.
    #[arg(long)]
    pub(crate) output_dir: Option<PathBuf>,

    /// Overwrite configuration file if it exists at destination.
    #[arg(long, default_value_t = false)]
    pub(crate) overwrite: bool,
}

/// Generate client configuration file that is understood by helper binaries and report collector
/// binary. This configuration describes the public interface to each helper: tls certificate and
/// the public key for HPKE encryption along with the endpoint to talk to.
///
/// It expects certain naming convention for TLS and encryption stuff, see [`Paths`] for more
/// details.
///
/// ## Errors
/// Returns an error if it can't find all three helper's public keys and TLS certs in the folder
/// specified in [`ConfGenArgs`] or if it fails to create the configuration file. Note that if file
/// already exists, without `--overwrite` flag specified, this command will also fail.
///
/// ## Panics
/// It does not panic, but compiler does not know about it.
///
/// [`ConfGenArgs`]: ConfGenArgs
/// [`Paths`]: crate::cli::paths::PathExt
pub fn setup(args: ConfGenArgs) -> Result<(), BoxError> {
    let clients_conf: [_; 3] = zip(args.hosts.iter(), args.ports)
        .enumerate()
        .map(|(id, (host, port))| {
            let id: u8 = u8::try_from(id).unwrap() + 1;
            HelperClientConf {
                host,
                port,
                tls_cert_file: args.keys_dir.helper_tls_cert(id),
                mk_public_key_file: args.keys_dir.helper_mk_public_key(id),
            }
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    if let Some(ref dir) = args.output_dir {
        fs::create_dir_all(dir)?;
    }
    let conf_file_path = args
        .output_dir
        .unwrap_or(args.keys_dir)
        .join("network.toml");
    let mut conf_file = File::options()
        .write(true)
        .create(true)
        .truncate(args.overwrite)
        .create_new(!args.overwrite)
        .open(&conf_file_path)
        .map_err(|e| format!("failed to create or open {}: {e}", conf_file_path.display()))?;

    gen_client_config(clients_conf, false, &mut conf_file)?;
    tracing::info!(
        "{} configuration file has been successfully created",
        conf_file_path.display()
    );
    Ok(())
}

#[derive(Debug)]
pub struct HelperClientConf<'a> {
    pub(crate) host: &'a str,
    pub(crate) port: u16,
    pub(crate) tls_cert_file: PathBuf,
    pub(crate) mk_public_key_file: PathBuf,
}

/// Generates client configuration file at the requested destination. The destination must exist
/// before this function is called
pub fn gen_client_config<'a>(
    clients_conf: [HelperClientConf<'a>; 3],
    use_http1: bool,
    conf_file: &'a mut File,
) -> Result<(), BoxError> {
    let mut peers = Vec::<Value>::with_capacity(3);
    for client_conf in clients_conf {
        let certificate = fs::read_to_string(&client_conf.tls_cert_file).map_err(|e| {
            format!(
                "Failed to open {}: {e}",
                client_conf.tls_cert_file.display()
            )
        })?;
        let mk_public_key = fs::read_to_string(&client_conf.mk_public_key_file).map_err(|e| {
            format!(
                "Failed to open {}: {e}",
                client_conf.mk_public_key_file.display()
            )
        })?;

        // Constructing toml directly because it avoids linking
        // a PEM library to serialize the certificate.
        let mut peer = Map::new();
        peer.insert(
            String::from("url"),
            Value::String(format!(
                "{host}:{port}",
                host = client_conf.host,
                port = client_conf.port
            )),
        );
        peer.insert(String::from("certificate"), Value::String(certificate));
        peer.insert(
            String::from("hpke"),
            Value::Table(encode_hpke(mk_public_key)),
        );
        peers.push(peer.into());
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

    Ok(conf_file.write_all(config_str.as_bytes())?)
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

    let Value::Array(peer_config_expected) = config_toml
        .get("peers")
        .expect("peer section must be present")
    else {
        panic!("peers section in toml config is not a table");
    };
    for (i, peer_config_actual) in nw_config.peers().iter().enumerate() {
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
        actual.map(|v| hex::encode(v.public_key.to_bytes()))
    );
}
