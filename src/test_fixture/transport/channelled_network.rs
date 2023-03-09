use crate::{
    helpers::{HelperIdentity, Transport},
    sync::{Arc, Weak},
    test_fixture::transport::InMemoryTransport,
};
use crate::helpers::transport::ChannelledTransport;
use crate::test_fixture::transport::channeled_transport::TransportCallbacks;
use crate::test_fixture::transport::InMemoryChannelledTransport;

/// Container for all active transports
#[derive(Clone)]
pub struct InMemoryNetwork {
    pub transports: [Arc<InMemoryChannelledTransport>; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        let [mut first, mut second, mut third] = [
            InMemoryChannelledTransport::with_stub_callbacks(1.try_into().unwrap()),
            InMemoryChannelledTransport::with_stub_callbacks(2.try_into().unwrap()),
            InMemoryChannelledTransport::with_stub_callbacks(3.try_into().unwrap()),
        ];
        first.connect(&mut second);
        second.connect(&mut third);
        third.connect(&mut first);

        Self {
            transports: [first.start(), second.start(), third.start()]
        }
    }
}

impl InMemoryNetwork {
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
    pub fn transport(&self, id: HelperIdentity) -> Option<impl ChannelledTransport> {
        self.transports
            .iter()
            .find(|t| t.identity() == id)
            .map(Arc::downgrade)
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn transports(&self) -> [impl ChannelledTransport + Clone; 3] {
        let transports: [Weak<InMemoryChannelledTransport>; 3] = self
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
