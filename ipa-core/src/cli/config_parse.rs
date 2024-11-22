use std::{
    fs::{self, File},
    io::Write,
    path::PathBuf,
    str::FromStr,
};

use config::Map;
use hpke::Serializable as _;
use hyper::Uri;
use serde::Deserialize;
use toml::{Table, Value};

use crate::{
    config::{ClientConfig, HpkeClientConfig, NetworkConfig, PeerConfig},
    error::BoxError,
    helpers::{HelperIdentity, TransportIdentity},
    net::{Helper, Shard},
    sharding::ShardIndex,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] config::ConfigError),
    #[error("Invalid uri: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    #[error("Invalid network size {0}")]
    InvalidNetworkSize(usize),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
    #[error("Missing shard URLs for peers {0:?}")]
    MissingShardUrls(Vec<usize>),
}

#[derive(Debug)]
pub struct HelperClientConf {
    pub(crate) host: String,
    pub(crate) port: u16,
    pub(crate) shard_port: u16,
    pub(crate) tls_cert_file: PathBuf,
    pub(crate) mk_public_key_file: PathBuf,
}

/// This struct is only used by [`parse_sharded_network_toml`] to parse the entire network.
/// Unlike [`NetworkConfig`], this one doesn't have identities.
#[derive(Clone, Debug, Deserialize)]
struct ShardedNetworkToml {
    pub peers: Vec<ShardedPeerConfigToml>,

    /// HTTP client configuration.
    #[serde(default)]
    pub client: ClientConfig,
}

impl ShardedNetworkToml {
    fn missing_shard_urls(&self) -> Vec<usize> {
        self.peers
            .iter()
            .enumerate()
            .filter_map(|(i, peer)| {
                if peer.shard_url.is_some() {
                    None
                } else {
                    Some(i)
                }
            })
            .collect()
    }
}

/// This struct is only used by [`parse_sharded_network_toml`] to generate [`PeerConfig`]. It
/// contains an optional `shard_url`.
#[derive(Clone, Debug, Deserialize)]
struct ShardedPeerConfigToml {
    #[serde(flatten)]
    pub config: PeerConfig,

    #[serde(default, with = "crate::serde::option::uri")]
    pub shard_url: Option<Uri>,
}

impl ShardedPeerConfigToml {
    /// Clones the inner Peer.
    fn to_mpc_peer(&self) -> PeerConfig {
        self.config.clone()
    }

    /// Create a new Peer but its url using [`ShardedPeerConfigToml::shard_url`].
    fn to_shard_peer(&self) -> PeerConfig {
        let mut shard_peer = self.config.clone();
        shard_peer.url = self.shard_url.clone().expect("Shard URL should be set");
        shard_peer
    }
}

/// Parses a [`ShardedNetworkToml`] from a network.toml file. Validates that sharding urls are set
///  if necessary. The number of peers needs to be a multiple of 3.
fn parse_sharded_network_toml(input: &str) -> Result<ShardedNetworkToml, Error> {
    use config::{Config, File, FileFormat};

    let parsed: ShardedNetworkToml = Config::builder()
        .add_source(File::from_str(input, FileFormat::Toml))
        .build()?
        .try_deserialize()?;

    if parsed.peers.len() % 3 != 0 {
        return Err(Error::InvalidNetworkSize(parsed.peers.len()));
    }

    // Validate sharding config is set
    let any_shard_url_set = parsed.peers.iter().any(|peer| peer.shard_url.is_some());
    if any_shard_url_set || parsed.peers.len() > 3 {
        let missing_urls = parsed.missing_shard_urls();
        if !missing_urls.is_empty() {
            return Err(Error::MissingShardUrls(missing_urls));
        }
    }

    Ok(parsed)
}

/// Generates client configuration file at the requested destination. The destination must exist
/// before this function is called
pub fn gen_client_config(
    clients_conf: impl Iterator<Item = HelperClientConf>,
    use_http1: bool,
    conf_file: &mut File,
) -> Result<(), BoxError> {
    let mut peers = Vec::<Value>::new();
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
        peer.insert(
            String::from("shard_url"),
            Value::String(format!(
                "{host}:{port}",
                host = client_conf.host,
                port = client_conf.shard_port
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
    let nw_config = parse_sharded_network_toml(config_str).expect("Can deserialize network config");

    let Value::Array(peer_config_expected) = config_toml
        .get("peers")
        .expect("peer section must be present")
    else {
        panic!("peers section in toml config is not a table");
    };
    for (i, peer_config_actual) in nw_config.peers.iter().enumerate() {
        assert_peer_config(&peer_config_expected[i], peer_config_actual);
    }
}

/// Validates that the resulting [`PeerConfig`] can be read by helper binary correctly.
///
/// [`PeerConfig`]: PeerConfig
fn assert_peer_config(expected: &Value, actual: &ShardedPeerConfigToml) {
    assert_eq!(
        expected.get("url").unwrap().as_str(),
        Some(actual.config.url.to_string()).as_deref()
    );
    assert_eq!(
        expected.get("shard_url").unwrap().as_str(),
        Some(actual.shard_url.as_ref().unwrap().to_string()).as_deref()
    );

    assert_hpke_config(
        expected.get("hpke").expect("hpke section must be present"),
        actual.config.hpke_config.as_ref(),
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

/// Extension to enable [`NetworkConfig<Helper>`] to read a deprecated non-sharded network.toml.
pub trait HelperNetworkConfigParseExt {
    fn from_toml_str(input: &str) -> Result<NetworkConfig<Helper>, Error>;
}

/// Reads config from string. Expects config to be toml format.
/// To read file, use `fs::read_to_string`
///
/// # Errors
/// if `input` is in an invalid format
impl HelperNetworkConfigParseExt for NetworkConfig<Helper> {
    fn from_toml_str(input: &str) -> Result<NetworkConfig<Helper>, Error> {
        let all_network = parse_sharded_network_toml(input)?;
        Ok(NetworkConfig::new_mpc(
            all_network
                .peers
                .iter()
                .map(ShardedPeerConfigToml::to_mpc_peer)
                .collect(),
            all_network.client.clone(),
        ))
    }
}

/// Reads a the config for a specific, single, sharded server from string. Expects config to be
/// toml format. The server in the network is specified via `id`, `shard_index` and
/// `shard_count`. This function expects shard urls to be set for all peers.
///
/// The first 3 peers corresponds to the leaders Ring. H1 shard 0, H2 shard 0, and H3 shard 0.
/// The next 3 correspond to the next ring with `shard_index` equals 1 and so on.
///
/// Other methods to read the network.toml exist depending on the use, for example
/// [`NetworkConfig::from_toml_str`] reads a non-sharded config.
/// TODO: There will be one to read the information relevant for the RC (doesn't need shard
/// info)
///
/// # Errors
/// if `input` is in an invalid format
///
/// # Panics
/// If you somehow provide an invalid non-sharded network toml
pub fn sharded_server_from_toml_str(
    input: &str,
    id: HelperIdentity,
    shard_index: ShardIndex,
    shard_count: ShardIndex,
    shard_port: Option<u16>,
) -> Result<(NetworkConfig<Helper>, NetworkConfig<Shard>), Error> {
    let all_network = parse_sharded_network_toml(input)?;

    let ix: usize = shard_index.as_index();
    let ix_count: usize = shard_count.as_index();
    // assert ix < count
    let mpc_id: usize = id.as_index();

    let mpc_network = NetworkConfig {
        peers: all_network
            .peers
            .iter()
            .map(ShardedPeerConfigToml::to_mpc_peer)
            .skip(ix * 3)
            .take(3)
            .collect(),
        client: all_network.client.clone(),
        identities: HelperIdentity::make_three().to_vec(),
    };
    let missing_urls = all_network.missing_shard_urls();
    if missing_urls.is_empty() {
        let shard_network = NetworkConfig {
            peers: all_network
                .peers
                .iter()
                .map(ShardedPeerConfigToml::to_shard_peer)
                .skip(mpc_id)
                .step_by(3)
                .take(ix_count)
                .collect(),
            client: all_network.client,
            identities: shard_count.iter().collect(),
        };
        Ok((mpc_network, shard_network))
    } else if missing_urls == [0, 1, 2] && shard_count == ShardIndex(1) {
        // This is the special case we're dealing with a non-sharded, single ring MPC.
        // Since the shard network will be of size 1, it can't really communicate with anyone else.
        // Hence we just create a config where I'm the only shard. We take the MPC configuration
        // and modify the port.
        let mut myself = ShardedPeerConfigToml::to_mpc_peer(all_network.peers.get(mpc_id).unwrap());
        let url = myself.url.to_string();
        let pos = url.rfind(':');
        let port = shard_port.expect("Shard port should be set");
        let new_url = if pos.is_some() {
            format!("{}{port}", &url[..=pos.unwrap()])
        } else {
            format!("{}:{port}", &url)
        };
        myself.url = Uri::from_str(&new_url).expect("Problem creating uri with sharded port");
        let shard_network = NetworkConfig {
            peers: vec![myself],
            client: all_network.client,
            identities: shard_count.iter().collect(),
        };
        Ok((mpc_network, shard_network))
    } else {
        return Err(Error::MissingShardUrls(missing_urls));
    }
}

#[cfg(test)]
mod tests {

}