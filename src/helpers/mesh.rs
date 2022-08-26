//!
//! This module contains implementations and traits that enable MPC helpers to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC helper service to do.
//!
use crate::helpers::error::Error;
use crate::helpers::Identity;
use crate::protocol::{RecordId, Step};
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Mesh {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(
        &mut self,
        dest: Identity,
        record: RecordId,
        msg: T,
    ) -> Result<(), Error>;

    /// Receive a message that is associated with the given record id.
    async fn receive<T: Message>(&mut self, source: Identity, record: RecordId)
        -> Result<T, Error>;

    /// Returns the unique identity of this helper.
    fn identity(&self) -> Identity;
}

/// This is the entry point for protocols to request communication when they require it.
pub trait Gateway<M: Mesh, S: Step> {
    /// Create or return an existing channel for a given step. Protocols can send messages to
    /// any helper through this channel (see `Mesh` interface for details).
    ///
    /// This method makes no guarantee that the communication channel will actually be established
    /// between this helper and every other one. The actual connection may be created only when
    /// `Mesh::send` or `Mesh::receive` methods are called.
    fn get_channel(&self, step: S) -> M;
}

pub mod mock {

    use std::collections::HashMap;

    use crate::helpers::error::Error;
    use crate::helpers::mesh::{Gateway, Mesh, Message};
    use crate::helpers::Identity;
    use crate::protocol::{QueryId, RecordId, Step};

    use async_trait::async_trait;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    #[derive(Debug)]
    pub struct TestWorld<S> {
        pub query_id: QueryId,
        pub gateways: [TestHelperGateway<S>; 3],
    }

    #[derive(Debug)]
    pub struct TestHelperGateway<S> {
        controller: Controller<S>,
    }

    #[derive(Debug)]
    pub struct TestMesh<S> {
        step: S,
        controller: Controller<S>,
    }

    /// Represents control messages sent between helpers to handle infrastructure requests.
    #[derive(Debug)]
    enum ControlMessage<S> {
        ConnectionRequest(Identity, S, Receiver<MessageEnvelope>),
        ConnectionEstablished(Identity, S),
    }

    #[derive(Debug)]
    struct MessageEnvelope {
        record_id: RecordId,
        payload: Box<[u8]>,
    }

    /// Represents the connection state between two helpers. Note that connection is not
    /// bi-directional. In order for helpers A and B to establish the bi-directional communication channel,
    /// they both need to initiate connection requests to each other.
    ///
    /// In future we may need to handle closing connections, but for now there is no need for that.
    #[derive(Debug, Clone)]
    enum ConnectionState {
        Listen,
        /// Request to connect has been sent and pending response from peer
        Pending(Sender<MessageEnvelope>),
        /// Connection is established and the other party is actively listening for incoming
        /// messages sent through this connection
        Established(Sender<MessageEnvelope>),
    }

    type ConnectionKey<S> = (Identity, S);

    /// Controller that is created per test helper. Handles control messages and establishes
    /// connections between this helper and others. Also keeps the queues of incoming messages
    /// indexed by source + step.
    #[derive(Debug)]
    struct Controller<S> {
        identity: Identity,
        peers: HashMap<Identity, Sender<ControlMessage<S>>>,
        connections: Arc<Mutex<HashMap<ConnectionKey<S>, ConnectionState>>>,
        buf: Arc<Mutex<HashMap<ConnectionKey<S>, Vec<MessageEnvelope>>>>,
    }

    impl<S: Step> TestHelperGateway<S> {
        fn new(controller: Controller<S>) -> Self {
            Self { controller }
        }
    }

    impl<S: Step> Gateway<TestMesh<S>, S> for TestHelperGateway<S> {
        fn get_channel(&self, step: S) -> TestMesh<S> {
            TestMesh {
                step,
                controller: self.controller.clone(),
            }
        }
    }

    #[async_trait]
    impl<S: Step> Mesh for TestMesh<S> {
        async fn send<T: Message>(
            &mut self,
            target: Identity,
            record_id: RecordId,
            msg: T,
        ) -> Result<(), Error> {
            let sender = self.controller.get_connection(target, self.step).await;

            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                record_id,
                payload: bytes,
            };

            sender.send(envelope).await.map_err(|e| Error::SendError {
                dest: target,
                inner: format!("Failed to send {:?}", e.0).into(),
            })?;

            Ok(())
        }

        async fn receive<T: Message>(
            &mut self,
            source: Identity,
            record: RecordId,
        ) -> Result<T, Error> {
            Ok(self.controller.receive(source, self.step, record).await)
        }

        fn identity(&self) -> Identity {
            self.controller.identity
        }
    }

    impl<S> Clone for Controller<S> {
        fn clone(&self) -> Self {
            Self {
                identity: self.identity,
                peers: self.peers.clone(),
                connections: Arc::clone(&self.connections),
                buf: Arc::clone(&self.buf),
            }
        }
    }

    impl<S: Step> Controller<S> {
        fn launch(
            identity: Identity,
            control_tx: HashMap<Identity, Sender<ControlMessage<S>>>,
            control_rx: Receiver<ControlMessage<S>>,
        ) -> Self {
            let controller = Self {
                identity,
                connections: Arc::new(Mutex::new(HashMap::new())),
                buf: Arc::new(Mutex::new(HashMap::new())),
                peers: control_tx,
            };

            controller.start(control_rx);

            controller
        }

        fn start(&self, mut rx: Receiver<ControlMessage<S>>) {
            let identity = self.identity;

            tokio::spawn({
                let controller = self.clone();
                async move {
                    while let Some(msg) = rx.recv().await {
                        match msg {
                            ControlMessage::ConnectionRequest(peer, step, peer_connection) => {
                                controller.connect(peer, step, peer_connection);

                                // Ack this request back to the sender
                                let sender = controller
                                    .peers
                                    .get(&peer)
                                    .unwrap_or_else(|| panic!("No peer with id {peer:?}"))
                                    .clone();

                                // it is important not to block the control loop so every async call
                                // must be handled in a separate tokio task
                                tokio::spawn({
                                    async move {
                                        sender
                                            .send(ControlMessage::ConnectionEstablished(
                                                identity, step,
                                            ))
                                            .await
                                            .unwrap();
                                    }
                                });
                            }
                            ControlMessage::ConnectionEstablished(peer, step) => {
                                controller.connection_acknowledged(peer, step);
                            }
                        }
                    }
                }
            });
        }

        fn connect(&self, peer: Identity, step: S, mut rx: Receiver<MessageEnvelope>) {
            assert_ne!(self.identity, peer);

            // start listening for incoming messages and move them from channel to the buffer
            tokio::spawn({
                let buf = Arc::clone(&self.buf);
                async move {
                    while let Some(msg) = rx.recv().await {
                        let mut buf = buf.lock().unwrap();
                        buf.entry((peer, step)).or_insert_with(Vec::new).push(msg);
                    }
                }
            });
        }

        fn connection_acknowledged(&self, peer: Identity, step: S) {
            let mut connections = self.connections.lock().unwrap();
            let conn_state = connections.get_mut(&(peer, step))
                .unwrap_or_else(|| panic!("Received an acknowledgment from {peer:?} for a connection that never been requested: step: {step:?}"));

            if let ConnectionState::Pending(sender) = conn_state {
                *conn_state = ConnectionState::Established(sender.clone());
            } else {
                panic!(
                    "Bad connection state for peer: {peer:?} and step: {step:?}: {conn_state:?}"
                );
            }
        }

        async fn get_connection(&self, peer: Identity, step: S) -> Sender<MessageEnvelope> {
            assert_ne!(self.identity, peer);

            loop {
                // Depending on connection status, request a new connection, spin and wait for
                // connection acknowledgment from peer or return the sender end of connection
                // if it is ready
                let control_message = {
                    let mut connections = self.connections.lock().unwrap();
                    let conn_state = connections
                        .entry((peer, step))
                        .or_insert_with(|| ConnectionState::Listen);

                    match conn_state {
                        ConnectionState::Listen => {
                            let (tx, rx) = channel(1);
                            *conn_state = ConnectionState::Pending(tx);

                            Some(ControlMessage::ConnectionRequest(self.identity, step, rx))
                        }
                        ConnectionState::Pending(_) => None,
                        ConnectionState::Established(sender) => {
                            return sender.clone();
                        }
                    }
                };

                if let Some(msg) = control_message {
                    self.peers
                        .get(&peer)
                        .unwrap_or_else(|| panic!("No peer with id {peer:?}"))
                        .send(msg)
                        .await
                        .unwrap();
                }
                tokio::task::yield_now().await;
            }
        }

        async fn receive<T: Message>(&self, peer: Identity, step: S, record_id: RecordId) -> T {
            // spin and wait until message with the same record id appears in the buffer
            // when it happens, pop it out, try to reinterpret its bytes as `T` and return
            loop {
                {
                    let mut buf = self.buf.lock().unwrap();
                    if let Some(msgs) = buf.get_mut(&(peer, step)) {
                        let l = msgs.len();
                        for i in 0..l {
                            if msgs[i].record_id == record_id {
                                msgs.swap(i, l - 1);
                                let envelope = msgs.pop().unwrap();
                                let obj: T = serde_json::from_slice(&envelope.payload).unwrap();

                                return obj;
                            }
                        }
                    }
                }

                tokio::task::yield_now().await;
            }
        }
    }

    #[must_use]
    pub fn make_world<S: Step>(query_id: QueryId) -> TestWorld<S> {
        let controllers = make_controllers();

        TestWorld {
            query_id,
            gateways: controllers.map(TestHelperGateway::new),
        }
    }

    #[must_use]
    fn make_controllers<S: Step>() -> [Controller<S>; 3] {
        let (mut senders, mut receivers) = (HashMap::new(), HashMap::new());
        for identity in Identity::all_variants() {
            let (tx, rx) = channel(1);
            senders.insert(identity, tx);
            receivers.insert(identity, rx);
        }

        Identity::all_variants().map(|identity| {
            let peer_senders = senders
                .iter()
                .filter(|(k, _)| ***k != identity)
                .map(|(k, v)| (**k, v.clone()))
                .collect::<HashMap<_, _>>();
            let rx = receivers.remove(&identity).unwrap();

            Controller::launch(identity, peer_senders, rx)
        })
    }
}
