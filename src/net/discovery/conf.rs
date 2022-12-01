use crate::net::discovery::{peer, Error, PeerDiscovery};
use std::str::FromStr;

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToHttpPeerConfig {
    origin: String,
    #[serde(with = "hex")]
    public_key: [u8; 32],
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToHttpConfig {
    h1: ToHttpPeerConfig,
    h2: ToHttpPeerConfig,
    h3: ToHttpPeerConfig,
}

/// Values that are serializable and read from config. May need further processing when translating
/// to [`peer::Config`].
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToConf {
    http: ToHttpConfig,
}

/// All config value necessary to discover other peer helpers of the MPC ring
pub struct Conf {
    peers: peer::Config,
}

impl Conf {
    fn from_file_conf(to_conf: &ToConf) -> Result<Self, Error> {
        Ok(Self {
            peers: peer::Config {
                http: [
                    Self::http_peer_config(&to_conf.http.h1)?,
                    Self::http_peer_config(&to_conf.http.h2)?,
                    Self::http_peer_config(&to_conf.http.h3)?,
                ],
            },
        })
    }

    fn http_peer_config(to_http_peer_config: &ToHttpPeerConfig) -> Result<peer::HttpConfig, Error> {
        Ok(peer::HttpConfig {
            origin: to_http_peer_config.origin.parse()?,
            public_key: to_http_peer_config.public_key.into(),
        })
    }
}

impl FromStr for Conf {
    type Err = Error;

    /// Reads config from string. Expects config to be toml format.
    /// To read file, use `fs::read_to_string`
    /// # Errors
    /// if the file does not exist, or is in an invalid format
    fn from_str(config_str: &str) -> Result<Self, Self::Err> {
        use config::{Config, File, FileFormat};

        let to_conf: ToConf = Config::builder()
            .add_source(File::from_str(config_str, FileFormat::Toml))
            .build()?
            .try_deserialize()?;

        Self::from_file_conf(&to_conf)
    }
}

impl PeerDiscovery for Conf {
    fn peers(&self) -> &peer::Config {
        &self.peers
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::helpers::Role;
    use hyper::Uri;

    const H1_PUBLIC_KEY: &str = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924";
    const H2_PUBLIC_KEY: &str = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b";
    const H3_PUBLIC_KEY: &str = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074";
    const H1_URI: &str = "http://localhost:3000/";
    const H2_URI: &str = "http://localhost:3001/";
    const H3_URI: &str = "http://localhost:3002/";
    const EXAMPLE_CONFIG: &str = r#"
[http]
    [http.h1]
        origin = "http://localhost:3000"
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

    [http.h2]
        origin = "http://localhost:3001"
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

    [http.h3]
        origin = "http://localhost:3002"
        public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
"#;

    fn hex_str_to_public_key(hex_str: &str) -> x25519_dalek::PublicKey {
        let pk_bytes: [u8; 32] = hex::decode(hex_str)
            .expect("valid hex string")
            .try_into()
            .expect("hex should be exactly 32 bytes");
        pk_bytes.into()
    }

    #[test]
    fn parse_config() {
        use config::{Config, File, FileFormat};

        let to_conf: ToConf = Config::builder()
            .add_source(File::from_str(EXAMPLE_CONFIG, FileFormat::Toml))
            .build()
            .unwrap()
            .try_deserialize()
            .expect("config should be valid");
        let conf = Conf::from_file_conf(&to_conf).expect("file should contain valid values");

        // H1
        assert_eq!(
            conf.peers.http[Role::H1].origin,
            H1_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers.http[Role::H1].public_key,
            hex_str_to_public_key(H1_PUBLIC_KEY)
        );

        // H2
        assert_eq!(
            conf.peers.http[Role::H2].origin,
            H2_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers.http[Role::H2].public_key,
            hex_str_to_public_key(H2_PUBLIC_KEY)
        );

        // H3
        assert_eq!(
            conf.peers.http[Role::H3].origin,
            H3_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers.http[Role::H3].public_key,
            hex_str_to_public_key(H3_PUBLIC_KEY)
        );
    }
}
