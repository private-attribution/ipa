//!
//! This module contains implementations and traits that enable MPC helpers to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers orchestrated into a "ring" - every helper instance has a peer
//! on the right side and on the left side. They simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC helper service to do.
//!
use crate::helpers::error::Error;
use crate::protocols::ProtocolId;
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {}

impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

/// Destination. Currently we only support Left and Right, but we could support the exact address
/// too
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HelperAddr {
    Left,
    Right,
}

/// Entry point to the system that enables MPC helpers to talk to each other. Every component
/// that need message exchange to drive itself to completion calls methods on this trait with id
/// argument that uniquely identifies its round of communication. Every helper executing the same
/// protocol must use the same id.
///
/// `Ring` trait can be used to send and receive messages and that is what methods on this trait
/// return. All messages will have the same protocol id
pub trait CommunicationGateway {
    type ChannelType: Ring;

    /// Creates new communication channel for the given protocol id. All helpers are orchestrated
    /// into a ring.
    fn ring_channel(&self, id: ProtocolId) -> Self::ChannelType;
}

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Ring {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(&mut self, dest: HelperAddr, msg: T) -> Result<(), Error>;

    /// Receive a given message from the `source`
    async fn receive<T: Message>(&mut self, source: HelperAddr) -> Result<T, Error>;
}

#[cfg(test)]
pub mod mock {
    use crate::helpers::error::Error;
    use crate::helpers::error::Error::{ReceiveError, SendError};
    use crate::helpers::ring::{CommunicationGateway, HelperAddr, Message, ProtocolId, Ring};
    use async_trait::async_trait;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    /// Entry point for all communications for a given helper. Keeps track of all protocols
    /// started by it and routes messages based on protocol identifiers they carry on with them.
    #[derive(Debug)]
    pub struct TestHelper {
        left: Sender<MessageEnvelope>,
        right: Sender<MessageEnvelope>,
        routing_table: Arc<Mutex<RoutingTable>>,
    }

    /// Communication channel for test helpers. Holds references to channel senders to send messages
    /// to the outside and owns the receivers (one per peer) to accept messages sent to it.
    /// Owner control the lifetime of protocol communication links:
    /// when this instance is dropped, link is removed.
    #[derive(Debug)]
    pub struct TestChannel {
        protocol_id: ProtocolId,
        table: Arc<Mutex<RoutingTable>>,
        senders: HashMap<HelperAddr, Sender<MessageEnvelope>>,
        receivers: HashMap<HelperAddr, Receiver<MessageEnvelope>>,
    }

    #[derive(Debug)]
    struct MessageEnvelope {
        source: HelperAddr,
        protocol_id: ProtocolId,
        payload: Box<[u8]>,
    }

    /// Communication infrastructure required for a given protocol. Senders represent outbound
    /// links provided to helpers to send messages, receivers allow helpers to receive messages.
    #[derive(Debug)]
    struct Route {
        outbound: HashMap<HelperAddr, Sender<MessageEnvelope>>,

        /// Receivers for messages sent to this helper within the same protocol id. Helper takes
        /// ownership of these receivers when connected and replaces the value with `None`.
        /// is set to `None` once test helper is connected to this instance
        inbound: Option<HashMap<HelperAddr, Receiver<MessageEnvelope>>>,
    }

    /// Keeps track of active protocols
    #[derive(Debug, Default)]
    struct RoutingTable {
        active_routes: HashMap<ProtocolId, Route>,
    }

    impl CommunicationGateway for TestHelper {
        type ChannelType = TestChannel;

        fn ring_channel(&self, protocol_id: ProtocolId) -> Self::ChannelType {
            let table = &mut *self.routing_table.lock().unwrap();

            // Take ownership of the receivers - if they've been created already, move them out
            // otherwise create them.
            let rx = match table.active_routes.entry(protocol_id) {
                Entry::Occupied(mut entry) => entry.get_mut().inbound.take().unwrap(),
                Entry::Vacant(entry) => entry.insert(Route::new()).inbound.take().unwrap(),
            };

            TestChannel {
                protocol_id,
                table: Arc::clone(&self.routing_table),
                senders: HashMap::from([
                    (HelperAddr::Left, self.left.clone()),
                    (HelperAddr::Right, self.right.clone()),
                ]),
                receivers: rx,
            }
        }
    }

    impl HelperAddr {
        /// To obtain source from destination we invert it - message send to the left helper
        /// is originated from helper on the right side.
        fn source(self) -> HelperAddr {
            match self {
                HelperAddr::Left => HelperAddr::Right,
                HelperAddr::Right => HelperAddr::Left,
            }
        }
    }

    #[async_trait]
    impl Ring for TestChannel {
        async fn send<T: Message>(&mut self, dest: HelperAddr, msg: T) -> Result<(), Error> {
            // inside the envelope we store the sender of the message (i.e. source)
            // but this method accepts the destination.
            let source = dest.source();

            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                source,
                protocol_id: self.protocol_id,
                payload: bytes,
            };

            let sender = self.senders.get(&dest).ok_or(SendError {
                dest,
                inner: "No sender for this destination".into(),
            })?;

            sender.send(envelope).await.map_err(|e| Error::SendError {
                dest,
                inner: Box::new(e) as _,
            })
        }

        async fn receive<T: Message>(&mut self, source: HelperAddr) -> Result<T, Error> {
            let rx = self
                .receivers
                .get_mut(&source)
                .expect("No receiver for {source}");

            loop {
                if let Some(msg_envelope) = rx.recv().await {
                    assert_eq!(msg_envelope.protocol_id, self.protocol_id);

                    let obj: T = serde_json::from_slice(&msg_envelope.payload).map_err(|e| {
                        ReceiveError {
                            source,
                            inner: Box::new(e),
                        }
                    })?;

                    return Ok(obj);
                }
            }
        }
    }

    impl Drop for TestChannel {
        fn drop(&mut self) {
            let table = &mut *self.table.lock().unwrap();
            table.active_routes.remove(&self.protocol_id);
        }
    }

    impl Route {
        /// Creates a new instance with new set of senders and receivers created (one pair per peer)
        fn new() -> Self {
            let (left_tx, left_rx) = channel(1);
            let (right_tx, right_rx) = channel(1);

            Self {
                outbound: HashMap::from([
                    (HelperAddr::Left, left_tx),
                    (HelperAddr::Right, right_tx),
                ]),
                inbound: Some(HashMap::from([
                    (HelperAddr::Left, left_rx),
                    (HelperAddr::Right, right_rx),
                ])),
            }
        }
    }

    impl TestHelper {
        fn new(
            mut this_rx: Receiver<MessageEnvelope>,
            left: Sender<MessageEnvelope>,
            right: Sender<MessageEnvelope>,
        ) -> Self {
            let table = Arc::new(Mutex::new(RoutingTable::default()));

            // Spawn a task that polls the receiver and routes messages to the appropriate sender
            // based on the protocol id. If there is no channel created,
            tokio::spawn({
                let table = Arc::clone(&table);
                async move {
                    while let Some(msg_envelope) = this_rx.recv().await {
                        let sender = {
                            let table = &mut *table.lock().unwrap();

                            match table.active_routes.entry(msg_envelope.protocol_id) {
                                Entry::Occupied(entry) => entry
                                    .get()
                                    .outbound
                                    .get(&msg_envelope.source)
                                    .unwrap()
                                    .clone(),
                                // if entry does not exist yet, create it
                                // it could be that other helper sent us message before
                                // this helper had a chance to call
                                Entry::Vacant(entry) => entry
                                    .insert(Route::new())
                                    .outbound
                                    .get(&msg_envelope.source)
                                    .unwrap()
                                    .clone(),
                            }
                        };

                        sender.send(msg_envelope).await.expect("Failed to receive");
                    }
                }
            });

            Self {
                left,
                right,
                routing_table: table,
            }
        }
    }

    /// Creates 3 test helper instances and orchestrates them into a ring.
    #[must_use]
    pub fn make_three() -> [TestHelper; 3] {
        let (tx1, rx1) = channel(1);
        let (tx2, rx2) = channel(1);
        let (tx3, rx3) = channel(1);

        [
            TestHelper::new(rx1, tx3.clone(), tx2.clone()),
            TestHelper::new(rx2, tx1.clone(), tx3),
            TestHelper::new(rx3, tx2, tx1),
        ]
    }

    #[tokio::test]
    async fn protocol_drop_cleans_up_resources() {
        let (tx, rx) = channel(1);
        let tr = TestHelper::new(rx, tx.clone(), tx);

        {
            let _r = tr.ring_channel(1.into());
            {
                let _r = tr.ring_channel(2.into());
                assert_eq!(tr.routing_table.lock().unwrap().active_routes.len(), 2);
            }
            assert_eq!(tr.routing_table.lock().unwrap().active_routes.len(), 1);
        }
        assert_eq!(tr.routing_table.lock().unwrap().active_routes.len(), 0);
    }
}
