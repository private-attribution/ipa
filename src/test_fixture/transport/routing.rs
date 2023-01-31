use crate::{
    error::BoxError,
    helpers::{
        query::QueryCommand, CommandEnvelope, CommandOrigin, HelperIdentity, SubscriptionType,
        TransportCommand,
    },
    task::JoinHandle,
};

use ::tokio::sync::{mpsc, oneshot};
use async_trait::async_trait;
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
    FromClient(QueryCommand),
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
            peer_links.push(ReceiverStream::new(link).map(move |command| (addr, command)));
        }

        let handle = tokio::spawn(async move {
            let mut routes = HashMap::default();
            loop {
                ::tokio::select! {
                    Some(command) = rx.recv() => {
                        match command {
                            SwitchCommand::Subscribe(SubscribeRequest { subscription, link, ack_tx }) => {
                                assert!(routes.insert(subscription, link).is_none());
                                ack_tx.send(()).unwrap();
                            }
                            SwitchCommand::FromClient(command) => {
                                TransportCommand::Query(command).dispatch(CommandOrigin::Other, &routes).await.expect("Failed to dispatch a command");
                            }
                        }
                    }
                    Some((origin, command)) = peer_links.next() => {
                        command.dispatch(CommandOrigin::Helper(origin), &routes).await.expect("Failed to dispatch a command");
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

    pub async fn subscribe(
        &self,
        subscription: SubscriptionType,
    ) -> ReceiverStream<CommandEnvelope> {
        let (tx, rx) = mpsc::channel(1);
        let (command, ack_rx) = SubscribeRequest::new(subscription, tx);
        self.tx
            .send(SwitchCommand::Subscribe(command))
            .await
            .unwrap();
        ack_rx.await.unwrap();

        ReceiverStream::new(rx)
    }

    pub fn identity(&self) -> HelperIdentity {
        self.identity
    }

    pub async fn direct_delivery(&self, c: QueryCommand) {
        self.tx.send(SwitchCommand::FromClient(c)).await.unwrap();
    }
}

impl Drop for Switch {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

#[derive(Debug, thiserror::Error)]
enum DispatchError {
    #[error("No listeners subscribed for {command:?}")]
    NoSubscribers { command: CommandEnvelope },
    #[error("Failed to send {command:?}")]
    SendFailed {
        command: CommandEnvelope,
        inner: BoxError,
    },
}

impl From<mpsc::error::SendError<CommandEnvelope>> for DispatchError {
    fn from(value: mpsc::error::SendError<CommandEnvelope>) -> Self {
        Self::SendFailed {
            command: value.0,
            inner: "channel closed".into(),
        }
    }
}

#[async_trait]
trait Dispatcher {
    async fn dispatch(
        self,
        origin: CommandOrigin,
        routes: &HashMap<SubscriptionType, mpsc::Sender<CommandEnvelope>>,
    ) -> Result<(), DispatchError>;
}

#[async_trait]
impl Dispatcher for TransportCommand {
    async fn dispatch(
        self,
        origin: CommandOrigin,
        routes: &HashMap<SubscriptionType, mpsc::Sender<CommandEnvelope>>,
    ) -> Result<(), DispatchError> {
        let sub = SubscriptionType::from(&self);
        let command = CommandEnvelope {
            origin,
            payload: self,
        };
        let route = routes.get(&sub);
        match route {
            Some(route) => Ok(route.send(command).await?),
            None => Err(DispatchError::NoSubscribers { command }),
        }
    }
}
