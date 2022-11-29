use crate::net::discovery::{peer, Error, PeerDiscovery};
use std::str::FromStr;

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToPeerHttpConfig {
    origin: String,
    #[serde(with = "hex")]
    public_key: [u8; 32],
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToPeerPrssConfig {
    #[serde(with = "hex")]
    public_key: [u8; 32],
}

#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToPeerConfig {
    http: ToPeerHttpConfig,
    prss: ToPeerPrssConfig,
}

/// Values that are serializable and read from config. May need further processing when translating
/// to [`peer::Config`].
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
struct ToConf {
    h1: ToPeerConfig,
    h2: ToPeerConfig,
    h3: ToPeerConfig,
}

/// All config value necessary to discover other peer helpers of the MPC ring
pub struct Conf {
    peers: [peer::Config; 3],
}

impl Conf {
    fn from_file_conf(to_conf: &ToConf) -> Result<Self, Error> {
        Ok(Self {
            peers: [
                Self::peer_config(&to_conf.h1)?,
                Self::peer_config(&to_conf.h2)?,
                Self::peer_config(&to_conf.h3)?,
            ],
        })
    }

    fn peer_config(to_peer_config: &ToPeerConfig) -> Result<peer::Config, Error> {
        Ok(peer::Config {
            http: peer::HttpConfig {
                origin: to_peer_config.http.origin.parse()?,
                public_key: to_peer_config.http.public_key.into(),
            },
            prss: peer::PrssConfig {
                public_key: to_peer_config.prss.public_key.into(),
            },
        })
    }
}

impl FromStr for Conf {
    type Err = Error;

    /// Reads config from `file_location`. Expects file to be json format
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
    fn peers(&self) -> [peer::Config; 3] {
        self.peers.clone()
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
[h1]
    [h1.http]
        origin = "http://localhost:3000"
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"
    [h1.prss]
        public_key = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924"

[h2]
    [h2.http]
        origin = "http://localhost:3001"
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"
    [h2.prss]
        public_key = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b"

[h3]
    [h3.http]
        origin = "http://localhost:3002"
        public_key = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074"
    [h3.prss]
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
            conf.peers[Role::H1].http.origin,
            H1_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers[Role::H1].http.public_key,
            hex_str_to_public_key(H1_PUBLIC_KEY)
        );

        // H2
        assert_eq!(
            conf.peers[Role::H2].http.origin,
            H2_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers[Role::H2].http.public_key,
            hex_str_to_public_key(H2_PUBLIC_KEY)
        );

        // H3
        assert_eq!(
            conf.peers[Role::H3].http.origin,
            H3_URI.parse::<Uri>().unwrap()
        );
        assert_eq!(
            conf.peers[Role::H3].http.public_key,
            hex_str_to_public_key(H3_PUBLIC_KEY)
        );
    }
}
