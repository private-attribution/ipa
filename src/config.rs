use axum_server::tls_rustls::RustlsConfig;
use hyper::Uri;
use serde::{Deserialize, Serialize};
use std::{io, path::PathBuf};

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
#[derive(Clone, Debug, Serialize, Deserialize)]
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer URL
    #[serde(with = "crate::uri")]
    pub url: Uri,

    /// Peer's TLS certificate or CA
    ///
    /// If the peer's TLS certificate can be verified using the system truststore, this may be omitted.
    ///
    /// If the peer's TLS certificate cannot be verified using the system truststore, or for a stronger
    /// check that the peer uses the expected PKI, either the peer certificate or the authority
    /// certificate that issues the peer's certificate may be specified here.
    ///
    /// If a certificate is specified here, only the specified certificate will be accepted. The system
    /// truststore will not be used.
    pub certificate: Option<String>,
}

impl PeerConfig {
    pub fn new(url: Uri) -> Self {
        Self {
            url,
            certificate: None,
        }
    }

    /// Returns `PeerConfig` for talking to the default self-signed server test cert.
    /// # Errors
    /// if cert is invalid
    /// # Panics
    /// never, but clippy doesn't understand that
    #[must_use]
    #[cfg(any(test, feature = "self-signed-certs"))]
    pub fn https_self_signed(port: u16) -> PeerConfig {
        PeerConfig {
            url: format!("https://localhost:{port}").parse().unwrap(),
            certificate: Some(TEST_CERT.to_owned()),
        }
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
        /// Path to file containing certificate
        certificate_file: PathBuf,

        /// Path to file containing private key
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

    /// If true, enable HTTPS. Otherwise, use insecure HTTP.
    pub https: bool,

    /// TLS configuration for helper-to-helper communication
    pub tls: Option<TlsConfig>,
}

impl ServerConfig {
    #[must_use]
    pub fn http() -> ServerConfig {
        ServerConfig {
            port: None,
            https: false,
            tls: None,
        }
    }

    #[must_use]
    pub fn http_port(port: u16) -> ServerConfig {
        ServerConfig {
            port: Some(port),
            https: false,
            tls: None,
        }
    }

    /// Returns `ServerConfig` instance configured with self-signed cert and key. Not intended to
    /// use in production, therefore it is hidden behind a feature flag.
    /// # Errors
    /// if cert is invalid
    #[must_use]
    #[cfg(any(test, feature = "self-signed-certs"))]
    pub fn https_self_signed() -> ServerConfig {
        ServerConfig {
            port: None,
            https: true,
            tls: Some(TlsConfig::Inline {
                certificate: TEST_CERT.to_owned(),
                private_key: TEST_KEY.to_owned(),
            }),
        }
    }

    /// Create a `RustlsConfig` for the `ServerConfig`.
    ///
    /// # Errors
    /// If there is a problem with the TLS configuration.
    pub async fn as_rustls_config(&self) -> io::Result<RustlsConfig> {
        match &self.tls {
            None => {
                // Using io::Error for this would not be my first choice, but it's
                // what the axum RustlsConfig::from_* routines do as well.
                Err(io::Error::new(
                    io::ErrorKind::Other,
                    "missing TLS configuration",
                ))
            }
            Some(TlsConfig::Inline {
                certificate,
                private_key,
            }) => {
                RustlsConfig::from_pem(
                    certificate.as_bytes().to_owned(),
                    private_key.as_bytes().to_owned(),
                )
                .await
            }
            Some(TlsConfig::File {
                certificate_file,
                private_key_file,
            }) => RustlsConfig::from_pem_file(&certificate_file, &private_key_file).await,
        }
    }
}

// This is here because it can be activated outside of tests with the
// `self-signed-certs` feature. It can probably be made test-only
// and moved to `crate::net::test`.
#[cfg(any(test, feature = "self-signed-certs"))]
const TEST_CERT: &str = "\
-----BEGIN CERTIFICATE-----
MIIBlDCCATugAwIBAgIICJ+d1TBXe0AwCgYIKoZIzj0EAwIwFDESMBAGA1UEAwwJ
bG9jYWxob3N0MB4XDTIzMDMyODAwMDIwOVoXDTIzMDYyNzAwMDIwOVowFDESMBAG
A1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEbuhfFs0U
Qae5KoQuCNBaJ81cpIWntGXSbaxJxkXNERkgcD9zf35HBAM7j8NYr3Kjh+W1lz80
qj6kHwAzq3fJSqN3MHUwFAYDVR0RBA0wC4IJbG9jYWxob3N0MA4GA1UdDwEB/wQE
AwICpDAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwHQYDVR0OBBYEFFvf
qKaSDivAf1+1H3wkItW8+GumMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwID
RwAwRAIgBqQPA/TAIh0J4GqUuclWkyDIZbaoUXSYbM4tYM//clMCIAaEHKVK5krK
MEv5kZ1e2xkmEQ+b3v7cAy3d58SjhW+v
-----END CERTIFICATE-----
";

#[cfg(any(test, feature = "self-signed-certs"))]
const TEST_KEY: &str = "\
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg2ZJo2GQ7gbCrj2PC
zQVb6BVsrGhV6E3GrDIAerI/HbKhRANCAARu6F8WzRRBp7kqhC4I0FonzVykhae0
ZdJtrEnGRc0RGSBwP3N/fkcEAzuPw1ivcqOH5bWXPzSqPqQfADOrd8lK
-----END PRIVATE KEY-----
";

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{helpers::HelperIdentity, test_fixture::config::TestConfigBuilder};
    use hyper::Uri;

    const URI_1: &str = "http://localhost:3000/";
    const URI_2: &str = "http://localhost:3001/";
    const URI_3: &str = "http://localhost:3002/";

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
        let conf = TestConfigBuilder::with_default_test_ports().build();

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
