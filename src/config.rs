use crate::helpers::HelperIdentity;

use hyper::{client::Builder, http::uri::Scheme, Uri};
use rustls_pemfile::Item;
use serde::{Deserialize, Deserializer, Serialize};
use tokio_rustls::rustls::Certificate;

use std::{
    array,
    borrow::Borrow,
    fmt::{Debug, Formatter},
    iter::Zip,
    path::PathBuf,
    slice,
};

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

    /// HTTP client configuration.
    #[serde(default)]
    pub client: ClientConfig,
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
            ..self
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
    /// The peer's end-entity TLS certificate must be specified here, unless HTTPS is disabled.
    /// In `network.toml`, the certificate must be in PEM format. It is converted to DER
    /// when the config is loaded.
    ///
    /// Verifying a peer's TLS certificate against the system truststore or a custom root of
    /// trust is not currently supported.
    #[serde(default, deserialize_with = "certificate_from_pem")]
    pub certificate: Option<Certificate>,

    /// public key which should be used to encrypt match keys
    pub matchkey_encryption_key: Option<String>,
}

impl PeerConfig {
    pub fn new(url: Uri, certificate: Option<Certificate>) -> Self {
        Self {
            url,
            certificate,
            matchkey_encryption_key: None,
        }
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

#[derive(Clone, Debug)]
pub enum MatchKeyEncryptionConfig {
    File {
        /// Path to file containing public key which encrypts match keys
        public_key_file: PathBuf,

        /// Path to file containing private key which decrypts match keys
        private_key_file: PathBuf,
    },
    Inline {
        /// Public key in hex format
        public_key: String,

        // Private key in hex format
        private_key: String,
    },
}

/// Configuration information for launching an instance of the helper party web service.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// Port to listen. If not specified, will ask Kernel to assign the port
    pub port: Option<u16>,

    /// If true, use insecure HTTP. Otherwise (default), use HTTPS.
    pub disable_https: bool,

    /// TLS configuration for helper-to-helper communication
    pub tls: Option<TlsConfig>,

    /// Configuration needed for encrypting and decrypting match keys
    pub matchkey_encryption_info: Option<MatchKeyEncryptionConfig>,
}

pub trait HyperClientConfigurator {
    fn configure<'a>(&self, client_builder: &'a mut Builder) -> &'a mut Builder;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub http_config: HttpClientConfigurator,
}

impl Default for ClientConfig {
    fn default() -> Self {
        ClientConfig::use_http2()
    }
}

impl ClientConfig {
    #[must_use]
    pub fn use_http2() -> Self {
        Self {
            http_config: HttpClientConfigurator::http2(),
        }
    }

    #[must_use]
    pub fn use_http1() -> Self {
        Self {
            http_config: HttpClientConfigurator::http1(),
        }
    }
}

impl<B: Borrow<ClientConfig>> HyperClientConfigurator for B {
    fn configure<'a>(&self, client_builder: &'a mut Builder) -> &'a mut Builder {
        self.borrow().http_config.configure(client_builder)
    }
}

/// Configure Hyper client to use the specific version of HTTP protocol when communicating with
/// MPC helpers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "version")]
#[serde(rename_all = "lowercase")]
pub enum HttpClientConfigurator {
    Http1(Http1Configurator),
    Http2(Http2Configurator),
}

impl HyperClientConfigurator for HttpClientConfigurator {
    fn configure<'a>(&self, client_builder: &'a mut Builder) -> &'a mut Builder {
        match self {
            HttpClientConfigurator::Http1(configurator) => configurator.configure(client_builder),
            HttpClientConfigurator::Http2(configurator) => configurator.configure(client_builder),
        }
    }
}

impl HttpClientConfigurator {
    #[must_use]
    pub fn http1() -> Self {
        Self::Http1(Http1Configurator::default())
    }

    #[must_use]
    pub fn http2() -> Self {
        Self::Http2(Http2Configurator::default())
    }
}

/// Clients will initiate connections using HTTP/1.1 but can upgrade to use HTTP/2 if server
/// suggests it.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Http1Configurator;

impl HyperClientConfigurator for Http1Configurator {
    fn configure<'a>(&self, client_builder: &'a mut Builder) -> &'a mut Builder {
        // See https://github.com/private-attribution/ipa/issues/650
        // and https://github.com/hyperium/hyper/issues/2312
        // This makes it very inefficient to use, so better to avoid HTTP 1.1
        client_builder.pool_max_idle_per_host(0)
    }
}

impl Debug for Http1Configurator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "http version: HTTP 1.1")
    }
}

/// Clients will use HTTP/2 exclusively. This will make client requests fail if server does not
/// support HTTP/2.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct Http2Configurator;

impl HyperClientConfigurator for Http2Configurator {
    fn configure<'a>(&self, client_builder: &'a mut Builder) -> &'a mut Builder {
        client_builder.http2_only(true)
    }
}

impl Debug for Http2Configurator {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "http version: HTTP 2")
    }
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
