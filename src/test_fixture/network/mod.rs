mod transport;
mod util;

use crate::{
    helpers::{HelperIdentity, Transport},
    sync::{Arc, Weak},
};

pub use transport::InMemoryTransport;
pub use util::DelayedTransport;
pub use transport::TransportCallbacks;
use crate::test_fixture::network::transport::{ReceiveQueryCallback, Setup, stub_callbacks};


trait Network {
    type Endpoint: Transport;

    fn get_endpoint(&self, id: HelperIdentity) -> Self::Endpoint;
    fn all_endpoints(&self) -> [Self::Endpoint; 3];
}

/// Container for all active transports
#[derive(Clone)]
pub struct InMemoryNetwork {
    pub transports: [Arc<InMemoryTransport>; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        Self::new([stub_callbacks(), stub_callbacks(), stub_callbacks()])
    }
}

impl InMemoryNetwork {
    pub fn new(callbacks: [TransportCallbacks; 3]) -> Self {
        let [mut first, mut second, mut third]: [_; 3] = HelperIdentity::make_three()
            .map(|(id)| Setup::new(id));

        first.connect(&mut second);
        second.connect(&mut third);
        third.connect(&mut first);

        let [cb1, cb2, cb3] = callbacks;

        Self {
            transports: [first.start(cb1), second.start(cb2), third.start(cb3)],
        }
    }

    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn helper_identities(&self) -> [HelperIdentity; 3] {
        self.transports
            .iter()
            .map(|t| t.identity())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    #[must_use]
    pub fn transport(&self, id: HelperIdentity) -> Option<impl Transport> {
        self.transports
            .iter()
            .find(|t| t.identity() == id)
            .map(Arc::downgrade)
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn transports(&self) -> [impl Transport + Clone; 3] {
        let transports: [Weak<InMemoryTransport>; 3] = self
            .transports
            .iter()
            .map(Arc::downgrade)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "What is dead may never die")
            .unwrap();
        transports
    }
}
