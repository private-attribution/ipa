mod demux;

use crate::helpers::{
    CommandEnvelope, HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError,
};
use crate::sync::Arc;
use async_trait::async_trait;
use demux::Demux;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use tokio::sync::mpsc::{channel, Sender};
use tokio_stream::wrappers::ReceiverStream;

pub struct InMemoryTransport {
    identity: HelperIdentity,
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
    demux: Demux,
}

impl Debug for InMemoryTransport {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "transport[{:?}]", self.identity)
    }
}

impl InMemoryTransport {
    pub fn new(identity: HelperIdentity) -> Self {
        Self {
            identity,
            peer_connections: HashMap::default(),
            demux: Demux::default(),
        }
    }

    /// Establish a unidirectional connection to the given peer
    pub fn connect(&mut self, dest: &mut Self) {
        let (tx, rx) = channel(1);
        self.peer_connections.insert(dest.identity.clone(), tx);
        dest.demux.new_peer(self.identity.clone(), rx);
    }

    pub fn identity(&self) -> &HelperIdentity {
        &self.identity
    }

    pub fn listen(&mut self) {
        self.demux.listen();
    }
}

#[async_trait]
impl Transport for Arc<InMemoryTransport> {
    type CommandStream = ReceiverStream<CommandEnvelope>;

    async fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream {
        match subscription_type {
            SubscriptionType::Administration => {
                unimplemented!()
            }
            SubscriptionType::Query(query_id) => self.demux.query_stream(query_id).await,
        }
    }

    async fn send(
        &self,
        destination: &HelperIdentity,
        command: TransportCommand,
    ) -> Result<(), TransportError> {
        Ok(self
            .peer_connections
            .get(destination)
            .unwrap()
            .send(command)
            .await?)
    }
}
