pub mod conf;
pub mod literal;

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
    use axum::http::Uri;
    use x25519_dalek::PublicKey;

    #[derive(Clone)]
    pub struct HttpConfig {
        pub origin: Uri,
        pub public_key: PublicKey,
    }

    #[derive(Clone)]
    pub struct PrssConfig {
        pub public_key: PublicKey,
    }

    #[derive(Clone)]
    pub struct Config {
        pub http: HttpConfig,
        pub prss: PrssConfig,
    }
}

/// Provides a set of peer helpers for an MPC computation. Also includes the client pointing to the
/// running server. Since the running server is aware of which [`Identity`] it is (`H1`, `H2`, or
/// `H3`), it should be able to use only the references to other servers. However, it's possible for
/// a server to send data to itself.
///
/// Any potential failures should be captured in the initialization of the implementer.
#[allow(clippy::module_name_repetitions)] // following standard naming convention
pub trait PeerDiscovery {
    fn peers(&self) -> &[peer::Config; 3];
}
