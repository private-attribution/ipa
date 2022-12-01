use crate::net::discovery::{peer, PeerDiscovery};

pub struct Literal {
    pub peers: peer::Config,
}

impl PeerDiscovery for Literal {
    fn peers(&self) -> &peer::Config {
        &self.peers
    }
}
