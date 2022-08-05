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
use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde::Serialize;
use std::fmt::Debug;


#[derive(Copy, Clone, Debug, Hash, Ord, PartialOrd, Eq, PartialEq)]
pub struct ProtocolId(u128);

impl From<u128> for ProtocolId {
    fn from(v: u128) -> Self {
        ProtocolId(v)
    }
}

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {
    fn protocol_id(&self) -> ProtocolId;
}


/// Destination. Currently we only support Left and Right, but we could support the exact address
/// too
#[derive(Debug, PartialEq, Eq, Hash, Clone, Copy)]
pub enum HelperAddr {
    Left,
    Right,
}

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Ring {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(&self, dest: HelperAddr, msg: T) -> Result<(), Error>;
    async fn receive<T: Message>(&self, source: HelperAddr) -> Result<T, Error>;
}

#[cfg(test)]
pub mod mock {
    use crate::helpers::error::Error;
    use crate::helpers::ring::{HelperAddr, Message, ProtocolId, Ring};
    use async_trait::async_trait;
    use std::any::TypeId;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::{channel, Receiver, Sender};

    /// Internally we represent all messages to be a sequence of bytes and store them inside
    /// a hashmap where each element is addressable by message type id and destination (i.e. who
    /// is the intended receiver of this message) + protocol id.
    type MessageBuf = HashMap<(HelperAddr, TypeId), Box<[u8]>>;

    /// Each message is packed inside an envelope with some meta information about it.
    #[derive(Debug)]
    struct MessageEnvelope {
        source: HelperAddr,
        protocol_id: ProtocolId,
        type_id: TypeId,
        payload: Box<[u8]>,
    }

    /// A mock implementation of `Ring` trait to be used in unit tests where all helpers are running
    /// inside the same process. Provides simple and inefficient implementation by buffering all messages
    /// on `send` and polling the buffer on `receive`. Message is determined to be the same if it has
    /// the same `TypeId` and helper address matches the destination. For example, message `Foo` sent
    /// to Helper 2 will be received and removed from the local buffer only when Helper 2 attempts to
    /// receive it.
    #[derive(Debug)]
    pub struct TestHelper {
        // Reference to helper channel on the left side
        left: Sender<MessageEnvelope>,

        // Reference to helper channel on the right side
        right: Sender<MessageEnvelope>,

        // buffer for messages sent to this helper
        buf: Arc<Mutex<MessageBuf>>,
    }

    #[derive(Debug)]
    pub struct TestHelperSetup {
        input: Sender<MessageEnvelope>,
        rx: Receiver<MessageEnvelope>,
        left: Option<Sender<MessageEnvelope>>,
        right: Option<Sender<MessageEnvelope>>,
    }

    impl TestHelperSetup {
        /// Constructs a new instance of test helper builder using the specified `buf_capacity`
        /// buffer capacity for the internally used channel.
        ///
        /// Every test helper instance to set up correctly requires both right and left side channels
        /// to be provided via this builder by calling `set_left` and `set_right` methods. `setup`
        /// method will consume this builder and produce a new instance of `TestHelper`.
        ///
        /// ## Panics
        /// Panics if Mutex used internally for synchronization is poisoned or if there are more
        /// than one message with the same type id and destination address arriving via `send` call.
        #[must_use]
        pub fn new(buf_capacity: usize) -> Self {
            let (tx, rx) = channel(buf_capacity);
            Self {
                input: tx,
                rx,
                left: None,
                right: None,
            }
        }

        fn set_left(&mut self, left: Sender<MessageEnvelope>) {
            self.left = Some(left);
        }

        fn set_right(&mut self, right: Sender<MessageEnvelope>) {
            self.right = Some(right);
        }

        fn get_input(&self) -> Sender<MessageEnvelope> {
            self.input.clone()
        }

        #[must_use]
        pub fn setup(self) -> TestHelper {
            TestHelper::new(
                self.rx,
                self.left.expect("left helper must be set"),
                self.right.expect("right helper must be set"),
            )
        }
    }

    impl TestHelper {
        fn new(
            mut rx: Receiver<MessageEnvelope>,
            left: Sender<MessageEnvelope>,
            right: Sender<MessageEnvelope>,
        ) -> Self {
            let buf = Arc::new(Mutex::new(HashMap::new()));

            tokio::spawn({
                let buf = Arc::clone(&buf);
                async move {
                    while let Some(item) = rx.recv().await {
                        // obtain an exclusive lock on the shared buffer
                        // and store the received message there. If there is already a message
                        // with the same type and destination, we simply panic and abort this task
                        let buf = &mut *buf.lock().unwrap();
                        match buf.entry((item.source, item.type_id)) {
                            Entry::Occupied(_entry) => {
                                panic!("Duplicated message {item:?}")
                            }
                            Entry::Vacant(entry) => entry.insert(item.payload),
                        };
                    }
                }
            });

            Self { left, right, buf }
        }
    }

    #[async_trait]
    impl Ring for TestHelper {
        async fn send<T: Message>(&self, dest: HelperAddr, msg: T) -> Result<(), Error> {
            // inside the envelope we store the sender of the message (i.e. source)
            // but this method accepts the destination. To obtain source from destination
            // we invert it - message send to the left helper is originated from helper on the
            // right side.
            let (target, source) = match dest {
                HelperAddr::Left => (&self.left, HelperAddr::Right),
                HelperAddr::Right => (&self.right, HelperAddr::Left),
            };

            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                protocol_id: msg.protocol_id(),
                type_id: TypeId::of::<T>(),
                source,
                payload: bytes,
            };

            target.send(envelope).await.map_err(|e| Error::SendError {
                dest,
                inner: Box::new(e) as _,
            })?;
            Ok(())
        }

        async fn receive<T: Message>(&self, source: HelperAddr) -> Result<T, Error> {
            let buf = Arc::clone(&self.buf);

            tokio::spawn(async move {
                loop {
                    {
                        let buf = &mut *buf.lock().unwrap();
                        let key = (source, TypeId::of::<T>());
                        if let Entry::Occupied(entry) = buf.entry(key) {
                            let payload = entry.remove();
                            let obj: T = serde_json::from_slice(&payload).unwrap();

                            return obj;
                        }
                    }

                    tokio::task::yield_now().await;
                }
            })
            .await
            .map_err(|e| Error::ReceiveError {
                source,
                inner: Box::new(e) as _,
            })
        }
    }

    /// Creates 3 test helper instances and orchestrates them into a ring.
    #[must_use]
    pub fn make_three() -> [TestHelper; 3] {
        let buf_capacity = 10;
        let mut helpers = [
            TestHelperSetup::new(buf_capacity),
            TestHelperSetup::new(buf_capacity),
            TestHelperSetup::new(buf_capacity),
        ];

        helpers[0].set_left(helpers[2].get_input());
        helpers[1].set_left(helpers[0].get_input());
        helpers[2].set_left(helpers[1].get_input());

        helpers[0].set_right(helpers[1].get_input());
        helpers[1].set_right(helpers[2].get_input());
        helpers[2].set_right(helpers[0].get_input());

        helpers.map(TestHelperSetup::setup)
    }
}
