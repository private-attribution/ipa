use crate::net::discovery::{peer, PeerDiscovery};

pub struct Literal {
    pub h1: peer::Config,
    pub h2: peer::Config,
    pub h3: peer::Config,
}

impl PeerDiscovery for Literal {
    fn peers(&self) -> [peer::Config; 3] {
        [self.h1.clone(), self.h2.clone(), self.h3.clone()]
    }
}
