use crate::helpers::HelperIdentity;
use crate::sync::Arc;
use crate::test_fixture::transport::InMemoryTransport;

/// Container for all active transports
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
            .map(|t| t.identity().clone())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }
}
