mod transport;

use ipa_step::Gate;
pub use transport::Setup;

use crate::{
    helpers::{HelperIdentity, TransportCallbacks},
    sync::{Arc, Weak},
};

pub type InMemoryTransport<G> = Weak<transport::InMemoryTransport<G>>;

/// Container for all active transports
#[derive(Clone)]
pub struct InMemoryNetwork<G: Gate> {
    pub transports: [Arc<transport::InMemoryTransport<G>>; 3],
}

impl<G: Gate> Default for InMemoryNetwork<G> {
    fn default() -> Self {
        Self::new([
            TransportCallbacks::default(),
            TransportCallbacks::default(),
            TransportCallbacks::default(),
        ])
    }
}

#[allow(dead_code)]
impl<G: Gate> InMemoryNetwork<G> {
    #[must_use]
    pub fn new(callbacks: [TransportCallbacks<InMemoryTransport<G>>; 3]) -> Self {
        let [mut first, mut second, mut third]: [_; 3] =
            HelperIdentity::make_three().map(Setup::new);

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

    /// Returns the transport to communicate with the given helper.
    ///
    /// ## Panics
    /// If [`HelperIdentity`] is somehow points to a non-existent helper, which shouldn't happen.
    #[must_use]
    pub fn transport(&self, id: HelperIdentity) -> InMemoryTransport<G> {
        self.transports
            .iter()
            .find(|t| t.identity() == id)
            .map_or_else(|| panic!("No transport for helper {id:?}"), Arc::downgrade)
    }

    #[allow(clippy::missing_panics_doc)]
    #[must_use]
    pub fn transports(&self) -> [InMemoryTransport<G>; 3] {
        let transports: [InMemoryTransport<G>; 3] = self
            .transports
            .iter()
            .map(Arc::downgrade)
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "What is dead may never die")
            .unwrap();
        transports
    }

    /// Reset all transports to the clear state.
    pub fn reset(&self) {
        for t in &self.transports {
            t.reset();
        }
    }
}
