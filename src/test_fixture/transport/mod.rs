mod network;
mod routing;
mod util;

pub use network::InMemoryNetwork;
pub use util::{DelayedTransport, FailingTransport};

use crate::helpers::{
    CommandEnvelope, HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError,
};
use crate::sync::Weak;
use async_trait::async_trait;
use routing::Switch;
use std::collections::HashMap;
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
        self.peer_connections
            .insert(dest.switch_setup.identity.clone(), tx);
        dest.switch_setup
            .add_peer(self.switch_setup.identity.clone(), rx);
    }

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
    pub fn setup(id: HelperIdentity) -> Setup {
        Setup::from(id)
    }

    /// Establish bidirectional connection between two transports
    pub fn link(a: &mut Setup, b: &mut Setup) {
        a.connect(b);
        b.connect(a);
    }

    pub fn identity(&self) -> &HelperIdentity {
        self.switch.identity()
    }
}

#[async_trait]
impl Transport for Weak<InMemoryTransport> {
    type CommandStream = ReceiverStream<CommandEnvelope>;

    async fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream {
        let this = self
            .upgrade()
            .unwrap_or_else(|| panic!("In memory transport is destroyed"));
        match subscription_type {
            SubscriptionType::QueryManagement => {
                unimplemented!()
            }
            SubscriptionType::Query(query_id) => this.switch.query_stream(query_id).await,
        }
    }

    async fn send(
        &self,
        destination: &HelperIdentity,
        command: TransportCommand,
    ) -> Result<(), TransportError> {
        let this = self
            .upgrade()
            .unwrap_or_else(|| panic!("In memory transport is destroyed"));
        Ok(this
            .peer_connections
            .get(destination)
            .unwrap()
            .send(command)
            .await?)
    }
}
