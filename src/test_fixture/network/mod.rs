mod transport;

use crate::{
    helpers::{HelperIdentity},
    sync::{Arc, Weak},
};

pub use transport::Setup;
use crate::helpers::TransportCallbacks;

pub type InMemoryTransport = Weak<transport::InMemoryTransport>;

/// Container for all active transports
#[derive(Clone)]
pub struct InMemoryNetwork {
    pub transports: [Arc<transport::InMemoryTransport>; 3],
}

impl Default for InMemoryNetwork {
    fn default() -> Self {
        Self::new([
            TransportCallbacks::default(),
            TransportCallbacks::default(),
            TransportCallbacks::default(),
        ])
    }
}

impl InMemoryNetwork {
    pub fn new(callbacks: [TransportCallbacks<'static, InMemoryTransport>; 3]) -> Self {
        let [mut first, mut second, mut third]: [_; 3] =
            HelperIdentity::make_three().map(|id| Setup::new(id));

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
    pub fn transport(&self, id: HelperIdentity) -> InMemoryTransport {
        self.transports
            .iter()
            .find(|t| t.identity() == id)
            .map(Arc::downgrade)
            .unwrap_or_else(|| panic!("No transport for helper {id:?}"))
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn transports(&self) -> [InMemoryTransport; 3] {
        let transports: [InMemoryTransport; 3] = self
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
