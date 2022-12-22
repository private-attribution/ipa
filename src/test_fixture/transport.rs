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

struct DemultiplexerStream;

impl Stream for DemultiplexerStream {
    type Item = TransportCommand;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

#[derive(Debug)]
enum MultiplexerCommand {
    Subscribe(SubscriptionType, Sender<CommandEnvelope>, oneshot::Sender<()>),
}

#[derive(Debug)]
enum MuxState {
    Idle(Receiver<MultiplexerCommand>, HashMap<HelperIdentity, Receiver<TransportCommand>>),
    Preparing,
    Listening(JoinHandle<()>)
}

struct Multiplexer {
    state: MuxState,
    tx: Sender<MultiplexerCommand>
}

impl Debug for Multiplexer {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "mux[{:?}]", self.state)
    }
}

#[derive(Default)]
struct QueryRouter {
    routes: HashMap<QueryId, Sender<CommandEnvelope>>
}

impl QueryRouter {
    async fn route(&self, origin: HelperIdentity, data: NetworkEventData) {
        let query_id = data.query_id;
        let sender = self.routes.get(&query_id)
            .unwrap_or_else(|| {
                tracing::warn!("No subscriber for query");
                panic!("No subscribers for {:?}", query_id);
            });
        sender.send(CommandEnvelope {
            origin,
            payload: TransportCommand::NetworkEvent(data)
        }).await.unwrap();
    }

    fn subscribe(&mut self, query_id: QueryId, sender: Sender<CommandEnvelope>) {
        assert!(self.routes.insert(query_id, sender).is_none());
    }
}

impl Multiplexer {
    pub fn new() -> Self {
        let (tx, mut rx) = channel(1);

        Self {
            state: MuxState::Idle(rx, HashMap::default()),
            tx
        }
    }

    pub fn new_peer(&mut self, peer_id: HelperIdentity, peer_rx: Receiver<TransportCommand>) {
        let MuxState::Idle(_, peers) = &mut self.state else {
            panic!("Not in Idle state");
        };

        assert!(peers.insert(peer_id, peer_rx).is_none());
    }

    pub fn listen(&mut self) {
        let MuxState::Idle(mut rx, peers) = mem::replace(&mut self.state, MuxState::Preparing) else {
            panic!("Not in Idle state");
        };

        let mut peer_links = SelectAll::new();
        peers.into_iter().for_each(|(addr, link)| {
            peer_links.push(ReceiverStream::new(link).map(move |command| (addr.clone(), command)));
        });

        let handle = tokio::spawn(async move {
            let mut query_router = QueryRouter::default();
            loop {
                ::tokio::select! {
                    Some(mux_command) = rx.recv() => {
                        match mux_command {
                            MultiplexerCommand::Subscribe(subscription, sender, ack_sender) => {
                                match subscription {
                                    SubscriptionType::Query(query_id) => {
                                        query_router.subscribe(query_id, sender);
                                        ack_sender.send(());
                                    },
                                    SubscriptionType::Administration => {
                                        unimplemented!()
                                    }
                                }
                            }
                        }
                    }
                    Some((origin, command)) = peer_links.next() => {
                        match command {
                            TransportCommand::NetworkEvent(data) => query_router.route(origin, data).await
                        }
                    }
                }
            };
        });

        self.state = MuxState::Listening(handle);
    }

    // pub fn listen(&self, peer_addr: HelperIdentity, channel: Receiver<TransportCommand>) {
    //     // listen only occurs when establishing connection between peers, so there should be no deadlock
    //     self.tx.blocking_send(MultiplexerCommand::Listen(peer_addr, channel)).unwrap()
    // }
    //
    pub async fn query_stream(&self, query_id: QueryId) -> ReceiverStream<CommandEnvelope> {
        let (tx, rx) = channel(1);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.tx.send(MultiplexerCommand::Subscribe(SubscriptionType::Query(query_id), tx, ack_tx))
            .await
            .unwrap();
        ack_rx.await.unwrap();

        ReceiverStream::new(rx)
    }
}

pub struct InMemoryTransport {
    identity: HelperIdentity,
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
    // TODO: demux
    mux: Multiplexer,
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
            mux: Multiplexer::new()
        }
    }

    /// Establish a unidirectional connection to the given peer
    pub fn connect(&mut self, dest: &mut Self) {
        let (tx, rx) = channel(1);
        self.peer_connections.insert(dest.identity.clone(), tx);
        dest.mux.new_peer(self.identity.clone(), rx);
    }

    pub fn identity(&self) -> &HelperIdentity {
        &self.identity
    }

    pub fn listen(&mut self) {
        self.mux.listen()
    }
}

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
                self.mux.query_stream(query_id).await
            }
        }
    }

    async fn send(&self, destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        Ok(self.peer_connections.get(destination).unwrap().send(command).await?)
    }
}