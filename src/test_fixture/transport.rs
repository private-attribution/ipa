use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use async_trait::async_trait;
use clap::command;
use futures::Stream;
use futures_util::stream::SelectAll;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument::WithSubscriber;
use crate::helpers::{HelperIdentity, NetworkEventData, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::protocol::QueryId;

struct DemultiplexerStream;

impl Stream for DemultiplexerStream {
    type Item = TransportCommand;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

#[derive(Debug)]
enum MultiplexerCommand {
    Listen(HelperIdentity, Receiver<TransportCommand>),
    Subscribe(SubscriptionType, Sender<TransportCommand>),
}

#[derive(Debug)]
struct Multiplexer {
    handle: JoinHandle<()>,
    tx: Sender<MultiplexerCommand>
}

#[derive(Default)]
struct QueryRouter {
    routes: HashMap<QueryId, Sender<TransportCommand>>
}

impl QueryRouter {
    async fn route(&self, data: NetworkEventData) {
        let query_id = data.query_id;
        let sender = self.routes.get(&query_id).unwrap_or_else(|| panic!("No subscribers for {:?}", query_id));
        sender.send(TransportCommand::NetworkEvent(data)).await.unwrap();
    }

    fn subscribe(&mut self, query_id: QueryId, sender: Sender<TransportCommand>) {
        assert!(self.routes.insert(query_id, sender).is_none());
    }
}

impl Multiplexer {
    pub fn new() -> Self {
        let (tx, mut rx) = channel(1);
        let handle = tokio::spawn(async move {
            let mut peer_links = SelectAll::new();
            let mut query_router = QueryRouter::default();
            let mut running_queries = HashMap::<QueryId, Sender<TransportCommand>>::new();
            loop {
                ::tokio::select! {
                    Some(mux_command) = rx.recv() => {
                        match mux_command {
                            MultiplexerCommand::Listen(addr, link) => {
                                peer_links.push(ReceiverStream::new(link).map(move |command| (addr.clone(), command)))
                            }
                            MultiplexerCommand::Subscribe(subscription, sender) => {
                                match subscription {
                                    SubscriptionType::Query(query_id) => {
                                        query_router.subscribe(query_id, sender)
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
                            TransportCommand::NetworkEvent(data) => query_router.route(data).await
                        }
                    }
                }
            };
        });

        Self {
            handle,
            tx
        }
    }

    pub fn listen(&self, peer_addr: HelperIdentity, channel: Receiver<TransportCommand>) {
        self.tx.send(MultiplexerCommand::Listen(peer_addr, channel));
    }

    pub async fn query_stream(&self, query_id: QueryId) -> ReceiverStream<TransportCommand> {
        let (tx, rx) = channel(1);
        self.tx.send(MultiplexerCommand::Subscribe(SubscriptionType::Query(query_id), tx)).await.unwrap();

        ReceiverStream::new(rx)
    }
}

struct Link {
    destination: HelperIdentity,
    inbound: Receiver<TransportCommand>,
    outbound: Sender<TransportCommand>,
}

#[derive(Debug)]
struct InMemoryTransport {
    peer_connections: HashMap<HelperIdentity, Sender<TransportCommand>>,
    // TODO: demux
    mux: Multiplexer,
}

impl InMemoryTransport {
    pub fn connect(&mut self, link: Link) {
        self.peer_connections.insert(link.destination.clone(), link.outbound);
        let (dest, inbound) = (link.destination, link.inbound);
        self.mux.listen(dest, inbound);
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    type CommandStream = ReceiverStream<TransportCommand>;

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