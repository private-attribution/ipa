mod demux;

use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::mem;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use async_trait::async_trait;
use clap::command;
use futures::{ready, Stream};
use futures_util::stream::SelectAll;
use pin_project::pin_project;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument::WithSubscriber;
use crate::helpers::{CommandEnvelope, HelperIdentity, NetworkEventData, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::protocol::QueryId;
use futures::StreamExt;
use tokio::sync::oneshot;
use demux::Demux;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;


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
        self.demux.listen()
    }
}

/// Channel stream wraps the generic stream of `TransportCommand` and folds these commands into
/// envelopes that carry additional information about the origin.
#[pin_project]
struct ChannelStream {
    origin: HelperIdentity,
    #[pin]
    inner: ReceiverStream<TransportCommand>
}

impl Stream for ChannelStream {
    type Item = CommandEnvelope;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let origin = self.origin.clone();
        let mut this = self.project();
        let item = ready!(this.inner.poll_next(cx));
        Poll::Ready(item.map(|v| CommandEnvelope { origin, payload: v }))
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.inner.size_hint()
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
            SubscriptionType::Query(query_id) => {
                self.demux.query_stream(query_id).await
            }
        }
    }

    async fn send(&self, destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        Ok(self.peer_connections.get(destination).unwrap().send(command).await?)
    }
}