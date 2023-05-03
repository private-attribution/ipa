use hyper::{http::uri::Scheme, Uri};
use serde::{Deserialize, Deserializer};
use x25519_dalek::PublicKey;

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
    peers: [PeerConfig; 3],
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

#[derive(Clone, Debug, Deserialize)]
pub struct HttpConfig {
    #[serde(deserialize_with = "pk_from_str")]
    pub public_key: PublicKey,
}

#[derive(Clone, Debug, Deserialize)]
pub struct PeerConfig {
    #[serde(with = "crate::uri")]
    pub origin: Uri,
    pub tls: HttpConfig,
}

fn pk_from_str<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
where
    D: Deserializer<'de>,
{
    let s: String = Deserialize::deserialize(deserializer)?;
    let mut buf = [0_u8; 32];
    hex::decode_to_slice(s, &mut buf).map_err(<D::Error as serde::de::Error>::custom)?;

    Ok(PublicKey::from(buf))
}

/// Configuration information for launching an instance of the helper party web service.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    // Report public key
    // Report private key
    /// Port to listen. If not specified, will ask Kernel to assign the port
    pub port: Option<u16>,

    /// Indicates whether to start HTTP or HTTPS endpoint
    pub scheme: Scheme,
    /*
    /// TLS certificate for helper-to-helper communication
    pub tls_certificate_file: Option<PathBuf>,

    /// TLS key for helper-to-helper communication
    pub tls_private_key_file: Option<PathBuf>,
    */
}

impl ServerConfig {
    #[must_use]
    pub fn with_http_and_port(port: u16) -> ServerConfig {
        ServerConfig {
            port: Some(port),
            scheme: Scheme::HTTP,
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{helpers::HelperIdentity, test_fixture::config::TestConfigBuilder};
    use hyper::Uri;

    const PUBLIC_KEY_1: &str = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924";
    const PUBLIC_KEY_2: &str = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b";
    const PUBLIC_KEY_3: &str = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074";
    const URI_1: &str = "http://localhost:3000/";
    const URI_2: &str = "http://localhost:3001/";
    const URI_3: &str = "http://localhost:3002/";

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
        assert_eq!(value1.origin, uri1);
        assert_eq!(value1.tls.public_key, hex_str_to_public_key(PUBLIC_KEY_1));

        let uri2 = URI_2.parse::<Uri>().unwrap();
        let id2 = HelperIdentity::try_from(2usize).unwrap();
        let value2 = &conf.network.peers()[id2];
        assert_eq!(value2.origin, uri2);
        assert_eq!(value2.tls.public_key, hex_str_to_public_key(PUBLIC_KEY_2));

        let uri3 = URI_3.parse::<Uri>().unwrap();
        let id3 = HelperIdentity::try_from(3usize).unwrap();
        let value3 = &conf.network.peers()[id3];
        assert_eq!(value3.origin, uri3);
        assert_eq!(value3.tls.public_key, hex_str_to_public_key(PUBLIC_KEY_3));
    }
}
