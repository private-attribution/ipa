mod network;
mod routing;
mod util;

pub use network::InMemoryNetwork;
pub use util::{DelayedTransport, FailingTransport};

use crate::{
    helpers::{
        query::QueryCommand, CommandEnvelope, HelperIdentity, SubscriptionType, Transport,
        TransportCommand, TransportError,
    },
    sync::Weak,
};
use async_trait::async_trait;
use routing::Switch;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use tokio::sync::mpsc::{channel, Sender};
use tokio_stream::wrappers::ReceiverStream;

/// In memory transport setup includes creating resources
/// to create a connection to every other peer in the network.
/// To finalize the setup and obtain [`InMemoryTransport`] instance
/// call [`listen`] method.
pub struct Setup {
    switch_setup: routing::Setup,
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
}

impl From<HelperIdentity> for Setup {
    fn from(id: HelperIdentity) -> Self {
        Self {
            switch_setup: routing::Setup::from(id),
            peer_connections: HashMap::default(),
        }
    }
}

impl Setup {
    pub fn connect(&mut self, dest: &mut Self) {
        let (tx, rx) = channel(1);
        self.peer_connections.insert(dest.switch_setup.identity, tx);
        dest.switch_setup.add_peer(self.switch_setup.identity, rx);
    }

    #[must_use]
    pub fn listen(self) -> InMemoryTransport {
        let switch = self.switch_setup.listen();

        InMemoryTransport {
            switch,
            peer_connections: self.peer_connections,
        }
    }
}

/// Implementation of `Transport` for in-memory testing. Uses tokio channels to exchange messages
/// with peers.
pub struct InMemoryTransport {
    switch: Switch,
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
}

impl InMemoryTransport {
    #[must_use]
    pub fn setup(id: HelperIdentity) -> Setup {
        Setup::from(id)
    }

    /// Establish bidirectional connection between two transports
    pub fn link(a: &mut Setup, b: &mut Setup) {
        a.connect(b);
        b.connect(a);
    }

    #[must_use]
    pub fn identity(&self) -> HelperIdentity {
        self.switch.identity()
    }

    /// Emulate client command delivery
    pub async fn deliver(&self, c: QueryCommand) {
        self.switch.direct_delivery(c).await;
    }
}

#[async_trait]
impl Transport for Weak<InMemoryTransport> {
    type CommandStream = ReceiverStream<CommandEnvelope>;

    fn identity(&self) -> HelperIdentity {
        let this = self
            .upgrade()
            .unwrap_or_else(|| panic!("In memory transport is destroyed"));

        InMemoryTransport::identity(&this)
    }

    async fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream {
        let this = self
            .upgrade()
            .unwrap_or_else(|| panic!("In memory transport is destroyed"));

        this.switch.subscribe(subscription_type).await
    }

    async fn send<C: Send + Into<TransportCommand>>(
        &self,
        destination: HelperIdentity,
        command: C,
    ) -> Result<(), TransportError> {
        let this = self
            .upgrade()
            .unwrap_or_else(|| panic!("In memory transport is destroyed"));
        Ok(this
            .peer_connections
            .get(&destination)
            .unwrap()
            .send(command.into())
            .await?)
    }
}

impl Debug for InMemoryTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport[id={:?}]", self.identity())
    }
}
