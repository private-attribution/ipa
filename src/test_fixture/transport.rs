use std::collections::HashMap;
use std::pin::Pin;
use std::task::{Context, Poll};
use async_trait::async_trait;
use futures::Stream;
use futures_util::stream::SelectAll;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::task::JoinHandle;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::ReceiverStream;
use tracing::instrument::WithSubscriber;
use crate::helpers::{HelperIdentity, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::protocol::QueryId;

struct DemultiplexerStream;

impl Stream for DemultiplexerStream {
    type Item = TransportCommand;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

enum MultiplexerCommand {
    Listen(HelperIdentity, Receiver<TransportCommand>),
}

#[derive(Debug)]
struct Multiplexer {
    handle: JoinHandle<()>,
    tx: Sender<MultiplexerCommand>
}

impl Multiplexer {
    pub fn new() -> Self {
        let (tx, mut rx) = channel(1);
        let handle = tokio::spawn(async move {
            let mut peer_links = SelectAll::new();
            let mut routers = HashMap::<SubscriptionType, Sender<TransportCommand>>::default();
            loop {
                ::tokio::select! {
                    Some(mux_command) = rx.recv() => {
                        match mux_command {
                            MultiplexerCommand::Listen(addr, link) => {
                                peer_links.push(ReceiverStream::new(link).map(move |command| (addr.clone(), command)))
                            }
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
        todo!()
    }

    pub fn query_stream(&self, query_id: QueryId) -> DemultiplexerStream {
        todo!()
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
    fn query_stream(&self, query_id: QueryId) -> DemultiplexerStream {
        todo!()
    }

    pub fn connect(&mut self, link: Link) {
        self.peer_connections.insert(link.destination.clone(), link.outbound);
        let (dest, inbound) = (link.destination, link.inbound);
        self.mux.listen(dest, inbound);
    }
}

#[async_trait]
impl Transport for InMemoryTransport {
    type CommandStream = DemultiplexerStream;

    fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream {
        match subscription_type {
            SubscriptionType::Administration => {
                unimplemented!()
            }
            SubscriptionType::Query(query_id) => {
                self.mux.query_stream(query_id)
            }
        }
    }

    async fn send(&self, destination: &HelperIdentity, command: TransportCommand) -> Result<(), TransportError> {
        Ok(self.peer_connections.get(destination).unwrap().send(command).await?)
    }
}