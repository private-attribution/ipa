mod conf;
mod literal;

pub use conf::Conf;
pub use literal::Literal;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] config::ConfigError),
    #[error("invalid uri: {0}")]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

pub mod peer {
    use hyper::Uri;
    #[cfg(feature = "enable-serde")]
    use serde::de::Error;
    #[cfg(feature = "enable-serde")]
    use serde::{Deserialize, Deserializer};
    use x25519_dalek::PublicKey;

    #[derive(Clone, Debug)]
    #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
    pub struct HttpConfig {
        #[cfg_attr(feature = "enable-serde", serde(deserialize_with = "pk_from_str"))]
        pub public_key: PublicKey,
    }

    #[derive(Clone, Debug)]
    #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
    pub struct Config {
        #[cfg_attr(feature = "enable-serde", serde(with = "crate::uri"))]
        pub origin: Uri,
        pub tls: HttpConfig,
    }

    #[cfg(feature = "enable-serde")]
    fn pk_from_str<'de, D>(deserializer: D) -> Result<PublicKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: String = Deserialize::deserialize(deserializer)?;
        let mut buf = [0_u8; 32];
        hex::decode_to_slice(s, &mut buf).map_err(D::Error::custom)?;

        Ok(PublicKey::from(buf))
    }
}

/// Provides a set of peer helpers for an MPC computation.
/// Any potential failures should be captured in the initialization of the implementer.
pub trait PeerDiscovery {
    fn peers(&self) -> &[peer::Config; 3];
}
