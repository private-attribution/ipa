use crate::net::discovery::{peer, PeerDiscovery};

pub struct Literal {
    peers: [peer::Config; 3],
}

impl Literal {
    pub fn new(h1: peer::Config, h2: peer::Config, h3: peer::Config) -> Self {
        Self {
            peers: [h1, h2, h3],
        }
    }
}

impl PeerDiscovery for Literal {
    fn peers(&self) -> &[peer::Config; 3] {
        &self.peers
    }
}
