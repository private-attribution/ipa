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
use crate::helpers::Identity;
use crate::protocol::Step;
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

type RecordStep<S> = (u128, S);

/// Trait for MPC helpers to communicate with each other. Helpers can send messages and
/// receive messages from a specific helper.
#[async_trait]
pub trait Ring<S: Step> {
    /// Send message to the destination. Implementations are free to choose whether it is required
    /// to wait until `dest` acknowledges message or simply put it to a outgoing queue
    async fn send<T: Message>(&self, target: Identity, step: RecordStep<S>, msg: T) -> Result<(), Error>;
    async fn receive<T: Message>(&mut self, source: Identity, step: RecordStep<S>) -> Result<T, Error>;

    /// Returns the unique identity of this helper.
    fn identity(&self) -> Identity;
}

#[cfg(test)]
pub mod mock {
    use crate::helpers::error::Error;
    use crate::helpers::ring::{HelperAddr, Message, RecordStep, Ring};
    use crate::helpers::Identity;
    use crate::protocol::{QueryId, Step};
    use async_trait::async_trait;
    use std::any::TypeId;
    use std::collections::hash_map::Entry;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc::{channel, Receiver, Sender};
    use tokio::task::{yield_now};

    /// Each message is packed inside an envelope with some meta information about it.
    #[derive(Debug)]
    struct MessageEnvelope {
        index: u128,
        payload: Box<[u8]>,
    }

    /// a combination of query id + step identifies the stream (communication channel) between
    /// two helpers. Within that stream, records are arranged (ordered) by the unique
    type StreamIndex<S> = (QueryId, S);
    type RecordStreamOutput<S> = Arc<Mutex<HashMap<StreamIndex<S>, Sender<MessageEnvelope>>>>;
    type RecordStreamInput<S> = HashMap<StreamIndex<S>, Receiver<MessageEnvelope>>;


    #[derive(Debug)]
    enum ControlMessage<S> {
        Establish(StreamIndex<S>, Sender<MessageEnvelope>),
    }

    /// TODO: description
    /// A mock implementation of `Ring` trait to be used in unit tests where all helpers are running
    /// inside the same process. Provides simple and inefficient implementation by buffering all messages
    /// on `send` and polling the buffer on `receive`. Message is determined to be the same if it has
    /// the same `TypeId` and helper address matches the destination. For example, message `Foo` sent
    /// to Helper 2 will be received and removed from the local buffer only when Helper 2 attempts to
    /// receive it.
    #[derive(Debug)]
    pub struct TestHelper<S> {
        /// Helper's identity
        identity: Identity,

        /// query we're executing
        query_id: QueryId,

        input: HashMap<Identity, RecordStreamInput<S>>,
        output: HashMap<Identity, RecordStreamOutput<S>>,

        control: HashMap<Identity, Sender<ControlMessage<S>>>,
    }

    impl<S: Step> TestHelper<S> {
        /// TODO description
        /// Constructs a new instance of test helper using the specified `buf_capacity` buffer
        /// capacity for the internally used channel.
        ///
        /// ## Panics
        /// Panics if Mutex used internally for synchronization is poisoned or if there are more
        /// than one message with the same type id and destination address arriving via `send` call.
        // #[must_use]
        fn new(id: Identity, control_receivers: HashMap<Identity, Receiver<ControlMessage<S>>>) -> Self {

            let input = control_receivers.keys()
                .map(|identity| (*identity, HashMap::new())).collect();
            let output: HashMap<_, _> = control_receivers.keys()
                .map(|identity| (*identity, Arc::new(Mutex::new(HashMap::new())))).collect();

            let handles: Vec<_> = control_receivers.into_iter().map(|(helper_identity, mut rx)| {
                let output_map = output[&helper_identity].clone();
                tokio::spawn(async move {
                    while let Some(msg) = rx.recv().await {
                        match msg {
                            ControlMessage::Establish((query_id, step), their_sender) => {
                                let mut output = output_map.lock().unwrap();
                                output.insert((query_id, step), their_sender);
                            }
                        }
                    }

                    ()
                })
            }).collect();

            Self {
                identity: id,
                query_id: QueryId,
                input,
                output,
                control: Default::default()
            }
        }
            // let (tx, mut rx) = channel::<MessageEnvelope>(buf_capacity);
            // let buf = Arc::new(Mutex::new(HashMap::new()));
            //
            // tokio::spawn({
            //     let buf = Arc::clone(&buf);
            //     async move {
            //         while let Some(item) = rx.recv().await {
            //             // obtain an exclusive lock on the shared buffer
            //             // and store the received message there. If there is already a message
            //             // with the same type and destination, we simply panic and abort this task
            //             let buf = &mut *buf.lock().unwrap();
            //             match buf.entry((item.source, item.step, item.type_id)) {
            //                 Entry::Occupied(_entry) => {
            //                     panic!("Duplicated message {item:?}")
            //                 }
            //                 Entry::Vacant(entry) => entry.insert(item.payload),
            //             };
            //         }
            //     }
            // });
            //
            // Self {
            //     identity: id,
            //     input_queue: tx,
            //     left: None,
            //     right: None,
            //     buf,
            // }
        // }

        // fn set_left(&mut self, left: Sender<MessageEnvelope<S>>) {
        //     self.left = Some(left);
        // }
        //
        // fn set_right(&mut self, right: Sender<MessageEnvelope<S>>) {
        //     self.right = Some(right);
        // }

        async fn get_sender(&self, target: Identity, step: RecordStep<S>) -> Sender<MessageEnvelope> {
            let mut peer_channel = self.output.get(&target).expect("No entry");
            let stream_id = (self.query_id, step.1);

            loop {
                {
                    let mut peer_channel = peer_channel.lock().unwrap();
                    if let Entry::Occupied(entry) =  peer_channel.entry(stream_id) {
                        return entry.get().clone()
                    }
                }
                yield_now().await
            }
        }

        async fn get_receiver(&mut self, source: Identity, step: RecordStep<S>) -> &mut Receiver<MessageEnvelope> {
            let mut peer_channel = self.input.get_mut(&source).expect("No entry");
            let stream_id = (self.query_id, step.1);

            peer_channel.entry(stream_id).or_insert_with(|| {
                let (tx, rx) = channel(1);
                let msg = ControlMessage::Establish(stream_id, tx);
                let control_sender = self.control.get(&source).unwrap().clone();

                tokio::spawn(async move {
                    control_sender.send(msg).await.unwrap();
                });

                rx
            })
        }
    }

    #[async_trait]
    impl<S: Step + Sync> Ring<S> for TestHelper<S> {
        async fn send<T: Message>(&self, target: Identity, step: RecordStep<S>, msg: T) -> Result<(), Error> {
            let target_sender = self.get_sender(target, step).await;
            let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
            let envelope = MessageEnvelope {
                index: step.0,
                payload: bytes,
            };

            target_sender.send(envelope).await.map_err(|e| Error::SendError {
                dest: target,
                inner: format!("Failed to send {:?}", e.0).into(),
            })?;

            Ok(())
        }

        async fn receive<T: Message>(&mut self, source: Identity, step: RecordStep<S>) -> Result<T, Error> {
            let mut source_rx = self.get_receiver(source, step).await;
            if let Some(msg) = source_rx.recv().await {
                if msg.index != step.0 {
                    Err(Error::ReceiveError {
                        source,
                        inner: format!("Message arrived out of order, expected: {}, got: {}", step.0, msg.index).into()
                    })
                } else {
                    let obj: T = serde_json::from_slice(&msg.payload).unwrap();
                    Ok(obj)
                }
            } else {
                Err(Error::ReceiveError {
                    source,
                    inner: "No message".into()
                })
            }
        }

        fn identity(&self) -> Identity {
            self.identity
        }
    }

    /// Creates 3 test helper instances and orchestrates them into a ring.
    #[must_use]
    pub fn make_three<S: Step>() -> [TestHelper<S>; 3] {

        let helpers = Identity::all_variants().map(|helper_id| {
            let mut control_map = HashMap::new();
            for &peer_id in Identity::all_variants() {
                if peer_id != helper_id {
                    let (tx, rx) = channel(1);
                    control_map.insert(peer_id, rx);
                }
            }

            TestHelper::new(helper_id, control_map)
        });

        helpers
        //
        // // let buf_capacity = 10;
        // let mut helpers = [
        //     TestHelper::new(Identity::H1, buf_capacity),
        //     TestHelper::new(Identity::H2, buf_capacity),
        //     TestHelper::new(Identity::H3, buf_capacity),
        // ];
        //
        // helpers[0].set_left(helpers[2].input_queue.clone());
        // helpers[1].set_left(helpers[0].input_queue.clone());
        // helpers[2].set_left(helpers[1].input_queue.clone());
        //
        // helpers[0].set_right(helpers[1].input_queue.clone());
        // helpers[1].set_right(helpers[2].input_queue.clone());
        // helpers[2].set_right(helpers[0].input_queue.clone());
        //
        // helpers
    }
}
