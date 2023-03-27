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
    pub fn new<C: ReceiveQueryCallback<Weak<InMemoryTransport>>>(callbacks: [TransportCallbacks<Weak<InMemoryTransport>>; 3]) -> Self {
        let [mut first, mut second, mut third]: [_; 3] = HelperIdentity::make_three().into_iter()
            .zip(callbacks)
            .map(|(id, callback)| {
            Setup::new(id, callback)
        }).collect::<Vec<_>>().try_into().map_err(|_| unreachable!()).unwrap();

        first.connect(&mut second);
        second.connect(&mut third);
        third.connect(&mut first);

        Self {
            transports: [first.start(), second.start(), third.start()]
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
