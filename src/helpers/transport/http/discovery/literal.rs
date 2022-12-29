use crate::helpers::{
    transport::http::discovery::{peer, PeerDiscovery},
    HelperIdentity,
};
use std::collections::HashMap;

pub struct Literal {
    peers_map: HashMap<HelperIdentity, peer::Config>,
}

impl Literal {
    pub fn new(
        h1: (HelperIdentity, peer::Config),
        h2: (HelperIdentity, peer::Config),
        h3: (HelperIdentity, peer::Config),
    ) -> Self {
        Self {
            peers_map: HashMap::from([h1, h2, h3]),
        }
    }
}

impl PeerDiscovery for Literal {
    fn peers_map(&self) -> &HashMap<HelperIdentity, peer::Config> {
        &self.peers_map
    }
}
