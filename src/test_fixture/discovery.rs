use crate::net::{discovery::PeerDiscovery, MpcHelperClient};

/// returns valid [`MpcHttpConnection`]s, but not pointing to real servers; only use this if the
/// clients will never be used. Intended for tests
pub struct Mock;

impl PeerDiscovery for Mock {
    fn peers(&self) -> [MpcHelperClient; 3] {
        [
            MpcHelperClient::with_str_addr("http://localhost:0").unwrap(),
            MpcHelperClient::with_str_addr("http://localhost:0").unwrap(),
            MpcHelperClient::with_str_addr("http://localhost:0").unwrap(),
        ]
    }
}
