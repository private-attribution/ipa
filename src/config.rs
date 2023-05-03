use hyper::{http::uri::Scheme, Uri};
use rustls_pemfile::Item;
use serde::{Deserialize, Deserializer};
use std::{array, iter::Zip, path::PathBuf, slice};
use tokio_rustls::rustls::Certificate;

use crate::helpers::HelperIdentity;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] config::ConfigError),
    #[error("invalid uri: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// Configuration information describing a helper network.
///
/// The most important thing this contains is discovery information for each of the participating
/// helpers.
#[derive(Clone, Debug, Deserialize)]
pub struct NetworkConfig {
    /// Information about each helper participating in the network. The order that helpers are
    /// listed here determines their assigned helper identities in the network. Note that while the
    /// helper identities are stable, roles are assigned per query.
    pub peers: [PeerConfig; 3],
}

impl NetworkConfig {
    /// Reads config from string. Expects config to be toml format.
    /// To read file, use `fs::read_to_string`
    ///
    /// # Errors
    /// if `input` is in an invalid format
    pub fn from_toml_str(input: &str) -> Result<Self, Error> {
        use config::{Config, File, FileFormat};

        let conf: Self = Config::builder()
            .add_source(File::from_str(input, FileFormat::Toml))
            .build()?
            .try_deserialize()?;

        Ok(conf)
    }

    pub fn peers(&self) -> &[PeerConfig; 3] {
        &self.peers
    }

    // Can maybe be replaced with array::zip when stable?
    pub fn enumerate_peers(
        &self,
    ) -> Zip<array::IntoIter<HelperIdentity, 3>, slice::Iter<PeerConfig>> {
        HelperIdentity::make_three()
            .into_iter()
            .zip(self.peers.iter())
    }

    /// # Panics
    /// If `PathAndQuery::from_str("")` fails
    #[must_use]
    pub fn override_scheme(self, scheme: &Scheme) -> NetworkConfig {
        NetworkConfig {
            peers: self.peers.map(|mut peer| {
                let mut parts = peer.url.into_parts();
                parts.scheme = Some(scheme.clone());
                // `http::uri::Uri::from_parts()` requires that a URI have a path if it has a
                // scheme. If the URI does not have a scheme, it is not required to have a path.
                if parts.path_and_query.is_none() {
                    parts.path_and_query = Some("".parse().unwrap());
                }
                peer.url = Uri::try_from(parts).unwrap();
                peer
            }),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    /// Peer URL
    #[serde(with = "crate::uri")]
    pub url: Uri,

    /// Peer's TLS certificate
    ///
    /// In `network.toml`, the certificate must be in PEM format. It is converted to DER
    /// when the config is loaded.
    ///
    /// Either the peer's TLS certificate, or the authority certificate that issues the peer
    /// certificate, must be specified here, unless HTTPS is disabled.
    ///
    /// It is possible to rely on the system truststore and omit this configuration if the peers use
    /// certificates from public CAs, but the client certificate verification is not currently
    /// configured to work off of the system truststore. (Besides the mechanics of accessing the
    /// system truststore, there is also the issue of what client CA names the server should send
    /// in that case.)
    #[serde(default, deserialize_with = "certificate_from_pem")]
    pub certificate: Option<Certificate>,
}

impl PeerConfig {
    pub fn new(url: Uri, certificate: Option<Certificate>) -> Self {
        Self { url, certificate }
    }
}

fn certificate_from_pem<'de, D>(deserializer: D) -> Result<Option<Certificate>, D::Error>
where
    D: Deserializer<'de>,
{
    let Some(s) = <Option<String> as Deserialize>::deserialize(deserializer)? else {
        return Ok(None);
    };
    match rustls_pemfile::read_one(&mut s.as_bytes()).map_err(serde::de::Error::custom)? {
        Some(Item::X509Certificate(bytes)) => Ok(Some(Certificate(bytes))),
        _ => Err(serde::de::Error::invalid_value(
            serde::de::Unexpected::Str(s.as_ref()),
            &"a certificate",
        )),
    }
}

/*
 * TODO(tls): delete this if not needed when TLS and config work is finished

fn pk_from_str<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut buf = [0_u8; 32];
    hex::decode_to_slice(s, &mut buf).map_err(<D::Error as serde::de::Error>::custom)?;

    Ok(PublicKey::from(buf))
}
*/

#[derive(Clone, Debug)]
pub enum TlsConfig {
    File {
        /// Path to file containing certificate in PEM format
        certificate_file: PathBuf,

        /// Path to file containing private key in PEM format
        private_key_file: PathBuf,
    },
    Inline {
        /// Certificate in PEM format
        certificate: String,

        // Private key in PEM format
        private_key: String,
    },
}

/// Configuration information for launching an instance of the helper party web service.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    // Report public key
    // Report private key
    /// Port to listen. If not specified, will ask Kernel to assign the port
    pub port: Option<u16>,

    /// If true, use insecure HTTP. Otherwise (default), use HTTPS.
    pub disable_https: bool,

    /// TLS configuration for helper-to-helper communication
    pub tls: Option<TlsConfig>,
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{helpers::HelperIdentity, net::test::TestConfigBuilder};
    use hyper::Uri;

    const URI_1: &str = "http://localhost:3000";
    const URI_2: &str = "http://localhost:3001";
    const URI_3: &str = "http://localhost:3002";

    #[allow(dead_code)] // TODO(tls) need to add back report public key configuration
    fn hex_str_to_public_key(hex_str: &str) -> x25519_dalek::PublicKey {
        let pk_bytes: [u8; 32] = hex::decode(hex_str)
            .expect("valid hex string")
            .try_into()
            .expect("hex should be exactly 32 bytes");
        pk_bytes.into()
    }

    #[test]
    fn parse_config() {
        let conf = TestConfigBuilder::with_http_and_default_test_ports().build();

        let uri1 = URI_1.parse::<Uri>().unwrap();
        let id1 = HelperIdentity::try_from(1usize).unwrap();
        let value1 = &conf.network.peers()[id1];
        assert_eq!(value1.url, uri1);

        let uri2 = URI_2.parse::<Uri>().unwrap();
        let id2 = HelperIdentity::try_from(2usize).unwrap();
        let value2 = &conf.network.peers()[id2];
        assert_eq!(value2.url, uri2);

        let uri3 = URI_3.parse::<Uri>().unwrap();
        let id3 = HelperIdentity::try_from(3usize).unwrap();
        let value3 = &conf.network.peers()[id3];
        assert_eq!(value3.url, uri3);
    }
}
