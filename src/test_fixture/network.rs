use crate::helpers::HelperIdentity;
use crate::sync::Arc;
use crate::test_fixture::transport::InMemoryTransport;
use std::fmt::Debug;

/// Container for all active transports
#[derive(Debug)]
pub struct InMemoryNetwork {
    pub transports: [Arc<InMemoryTransport>; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        let [mut first, mut second, mut third]: [InMemoryTransport; 3] = (0..3)
            .map(|v| InMemoryTransport::new(HelperIdentity::from(v)))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // it is a bit tedious, is there a better way?
        first.connect(&mut second);
        first.connect(&mut third);
        second.connect(&mut first);
        second.connect(&mut third);
        third.connect(&mut first);
        third.connect(&mut second);

        first.listen();
        second.listen();
        third.listen();

        Self {
            transports: [Arc::new(first), Arc::new(second), Arc::new(third)],
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
