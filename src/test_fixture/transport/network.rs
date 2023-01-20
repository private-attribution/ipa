use crate::helpers::{HelperIdentity, Transport};
use crate::sync::Arc;
use crate::sync::Weak;
use crate::test_fixture::transport::InMemoryTransport;

/// Container for all active transports
#[derive(Clone)]
pub struct InMemoryNetwork {
    pub transports: [Arc<InMemoryTransport>; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        let [mut first, mut second, mut third] = [
            InMemoryTransport::setup(1.try_into().unwrap()),
            InMemoryTransport::setup(2.try_into().unwrap()),
            InMemoryTransport::setup(3.try_into().unwrap()),
        ];

        InMemoryTransport::link(&mut first, &mut second);
        InMemoryTransport::link(&mut second, &mut third);
        InMemoryTransport::link(&mut third, &mut first);

        Self {
            transports: [first.listen(), second.listen(), third.listen()].map(Arc::new),
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
    pub fn transport(&self, id: HelperIdentity) -> Option<impl Transport + Clone> {
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
            .unwrap();
        transports
    }
}
