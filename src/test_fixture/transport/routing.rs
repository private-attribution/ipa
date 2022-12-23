use crate::helpers::{
    CommandEnvelope, CommandOrigin, HelperIdentity, SubscriptionType, TransportCommand,
};
use crate::protocol::{QueryId, Step};
use crate::task::JoinHandle;
use ::tokio::sync::{mpsc, oneshot};
use futures::StreamExt;
use futures_util::stream::SelectAll;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;

#[derive(Debug)]
enum SwitchCommand {
    Subscribe(SubscribeRequest),
}

struct SubscribeRequest {
    subscription: SubscriptionType,
    link: mpsc::Sender<CommandEnvelope>,
    ack_tx: oneshot::Sender<()>,
}

impl Debug for SubscribeRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Subscribe[{:?}]", self.subscription)
    }
}

impl SubscribeRequest {
    pub fn new(
        subscription: SubscriptionType,
        link: mpsc::Sender<CommandEnvelope>,
    ) -> (Self, oneshot::Receiver<()>) {
        let (ack_tx, ack_rx) = oneshot::channel();
        (
            Self {
                subscription,
                link,
                ack_tx,
            },
            ack_rx,
        )
    }

    pub fn acknowledge(self) {
        self.ack_tx.send(()).unwrap();
    }

    pub fn subscription(&self) -> SubscriptionType {
        self.subscription
    }

    pub fn sender(&self) -> mpsc::Sender<CommandEnvelope> {
        self.link.clone()
    }
}

#[derive(Debug)]
pub struct Setup {
    pub identity: HelperIdentity,
    peers: HashMap<HelperIdentity, mpsc::Receiver<TransportCommand>>,
}

impl From<HelperIdentity> for Setup {
    fn from(identity: HelperIdentity) -> Self {
        Self {
            identity,
            peers: HashMap::default(),
        }
    }
}

impl Setup {
    pub fn add_peer(&mut self, peer_id: HelperIdentity, peer_rx: mpsc::Receiver<TransportCommand>) {
        assert!(self.peers.insert(peer_id, peer_rx).is_none());
    }

    pub(super) fn listen(self) -> Switch {
        Switch::new(self)
    }
}

/// Takes care of forwarding commands received from multiple links (one link per peer)
/// to the subscribers
pub(super) struct Switch {
    identity: HelperIdentity,
    tx: mpsc::Sender<SwitchCommand>,
    handle: JoinHandle<()>,
}

impl Switch {
    fn new(setup: Setup) -> Self {
        let (tx, mut rx) = mpsc::channel(1);

        let mut peer_links = SelectAll::new();
        for (addr, link) in setup.peers {
            peer_links.push(ReceiverStream::new(link).map(move |command| (addr.clone(), command)));
        }

        let handle = tokio::spawn(async move {
            let mut query_router = QueryCommandRouter::default();
            loop {
                ::tokio::select! {
                    Some(command) = rx.recv() => {
                        match command {
                            SwitchCommand::Subscribe(subscribe_command) => {
                                match subscribe_command.subscription() {
                                    SubscriptionType::Query(query_id) => {
                                        tracing::trace!("Subscribed to receive commands for query {query_id:?}");
                                        query_router.subscribe(query_id, subscribe_command.sender());
                                        subscribe_command.acknowledge();
                                    },
                                    SubscriptionType::QueryManagement => {
                                        unimplemented!()
                                    }
                                }
                            }
                        }
                    }
                    Some((origin, command)) = peer_links.next() => {
                        match command {
                            TransportCommand::StepData(query, step, payload) => query_router.route(origin, query, step, payload).await
                        }
                    }
                    else => {
                        tracing::debug!("All channels are closed and switch is terminated");
                        break;
                    }
                }
            }
        }.instrument(tracing::info_span!("transport_loop", id=?setup.identity).or_current()));

        Self {
            identity: setup.identity,
            handle,
            tx,
        }
    }

    pub async fn query_stream(&self, query_id: QueryId) -> ReceiverStream<CommandEnvelope> {
        let (tx, rx) = mpsc::channel(1);
        let (command, ack_rx) = SubscribeRequest::new(SubscriptionType::Query(query_id), tx);
        self.tx
            .send(SwitchCommand::Subscribe(command))
            .await
            .unwrap();
        ack_rx.await.unwrap();

        ReceiverStream::new(rx)
    }

    pub fn identity(&self) -> &HelperIdentity {
        &self.identity
    }
}

impl Drop for Switch {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Default)]
struct QueryCommandRouter {
    routes: HashMap<QueryId, mpsc::Sender<CommandEnvelope>>,
}

impl QueryCommandRouter {
    async fn route(&self, origin: HelperIdentity, query_id: QueryId, step: Step, payload: Vec<u8>) {
        let sender = self
            .routes
            .get(&query_id)
            .unwrap_or_else(|| panic!("No subscribers for {query_id:?}"));

        sender
            .send(CommandEnvelope {
                origin: CommandOrigin::Helper(origin),
                payload: TransportCommand::StepData(query_id, step, payload),
            })
            .await
            .unwrap();
    }

    fn subscribe(&mut self, query_id: QueryId, sender: mpsc::Sender<CommandEnvelope>) {
        assert!(self.routes.insert(query_id, sender).is_none());
    }
}
