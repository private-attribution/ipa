use crate::net::discovery::{peer, Error, PeerDiscovery};

/// All config value necessary to discover other peer helpers of the MPC ring
#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
pub struct Conf {
    peers: [peer::Config; 3],
}

impl Conf {
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
}

impl PeerDiscovery for Conf {
    fn peers(&self) -> &[peer::Config; 3] {
        &self.peers
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::helpers::Role;
    use crate::test_fixture::net::localhost_config;
    use hyper::Uri;

    const H1_PUBLIC_KEY: &str = "13ccf4263cecbc30f50e6a8b9c8743943ddde62079580bc0b9019b05ba8fe924";
    const H2_PUBLIC_KEY: &str = "925bf98243cf70b729de1d75bf4fe6be98a986608331db63902b82a1691dc13b";
    const H3_PUBLIC_KEY: &str = "12c09881a1c7a92d1c70d9ea619d7ae0684b9cb45ecc207b98ef30ec2160a074";
    const H1_URI: &str = "http://localhost:3000/";
    const H2_URI: &str = "http://localhost:3001/";
    const H3_URI: &str = "http://localhost:3002/";

    fn hex_str_to_public_key(hex_str: &str) -> x25519_dalek::PublicKey {
        let pk_bytes: [u8; 32] = hex::decode(hex_str)
            .expect("valid hex string")
            .try_into()
            .expect("hex should be exactly 32 bytes");
        pk_bytes.into()
    }

    #[test]
    fn parse_config() {
        let conf = localhost_config([3000, 3001, 3002]);

        // H1
        assert_eq!(conf.peers[Role::H1].origin, H1_URI.parse::<Uri>().unwrap());
        assert_eq!(
            conf.peers[Role::H1].tls.public_key,
            hex_str_to_public_key(H1_PUBLIC_KEY)
        );

        // H2
        assert_eq!(conf.peers[Role::H2].origin, H2_URI.parse::<Uri>().unwrap());
        assert_eq!(
            conf.peers[Role::H2].tls.public_key,
            hex_str_to_public_key(H2_PUBLIC_KEY)
        );

        // H3
        assert_eq!(conf.peers[Role::H3].origin, H3_URI.parse::<Uri>().unwrap());
        assert_eq!(
            conf.peers[Role::H3].tls.public_key,
            hex_str_to_public_key(H3_PUBLIC_KEY)
        );
    }
}
