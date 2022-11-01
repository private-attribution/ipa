pub mod config;
#[cfg(test)]
pub mod mock;

use crate::net::MpcHelperClient;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    ParseError(#[from] serde_json::Error),
    #[error(transparent)]
    IOError(#[from] std::io::Error),
}

/// Provides a set of peer helpers for an MPC computation. Also includes the client pointing to the
/// running server. Since the running server is aware of which [`Identity`] it is (`H1`, `H2`, or
/// `H3`), it should be able to use only the references to other servers. However, it's possible for
/// a server to send data to itself.
///
/// Any potential failures should be captured in the initialization of the implementer.
#[allow(clippy::module_name_repetitions)] // following standard naming convention
pub trait PeerDiscovery {
    fn peers(&self) -> [MpcHelperClient; 3];
}
