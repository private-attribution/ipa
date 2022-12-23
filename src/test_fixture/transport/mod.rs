pub mod network;
mod routing;

use crate::helpers::{
    CommandEnvelope, HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError,
};
use crate::sync::Weak;
use async_trait::async_trait;
use routing::Switch;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use tokio::sync::mpsc::{channel, Sender};
use tokio_stream::wrappers::ReceiverStream;

/// Implementation of `Transport` for in-memory testing. Uses tokio channels to exchange messages
/// with peers.
pub struct InMemoryTransport {
    identity: HelperIdentity,
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
    switch: Switch,
}

impl Debug for InMemoryTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport[{:?}]", self.identity)
    }
}

impl InMemoryTransport {
    pub fn new(identity: HelperIdentity) -> Self {
        Self {
            identity: identity.clone(),
            peer_connections: HashMap::default(),
            switch: Switch::new(identity),
        }
    }

    /// Establish a unidirectional connection to the given peer
    pub fn connect(&mut self, dest: &mut Self) {
        let (tx, rx) = channel(1);
        self.peer_connections.insert(dest.identity.clone(), tx);
        dest.switch.new_peer(self.identity.clone(), rx);
    }

    pub fn identity(&self) -> &HelperIdentity {
        &self.identity
    }

    pub fn listen(&mut self) {
        self.switch.listen();
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
