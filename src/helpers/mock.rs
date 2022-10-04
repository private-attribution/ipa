/// Provides an implementation of `Gateway` and `Mesh` suitable for unit tests.
use std::collections::HashMap;

use crate::helpers::error::Error;
use crate::helpers::mesh::{Message};
use crate::helpers::Identity;
use crate::protocol::{RecordId, Step};

use async_trait::async_trait;
use futures::Stream;
use futures_util::stream::SelectAll;
use futures_util::StreamExt;
use std::collections::hash_map::Entry;
use std::fmt::{Debug, Formatter};
use std::marker::PhantomData;
use std::sync::{Arc, Mutex};

use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tracing::Instrument;
use crate::field::Field;
use crate::helpers::fabric::{ChannelId, Fabric, MessageEnvelope};
use crate::helpers::fabric::CommunicationChannel;
use crate::secret_sharing::Replicated;

// /// Gateway is just the proxy for `Controller` interface to provide stable API and hide
// /// `Controller`'s dependencies
// #[derive(Debug)]
// pub struct TestHelperGateway<S, F> {
//     controller: Controller<S, F>,
// }
//
// /// This is the communication end exposed to protocols to send messages between helpers.
// /// It locks in the step, so all information sent through it is implicitly associated with
// /// the step used to create this instance. Along with `QueryId` that is used to create the
// /// test world, it is used to uniquely identify the "stream" of records flowing between
// /// helper instances
// #[derive(Debug)]
// pub struct TestMesh<S, F> {
//     step: S,
//     controller: Controller<S, F>,
// }
//
/// Local buffer for messages that are either awaiting requests to receive them or requests
/// that are pending message reception.
/// Right now it is backed by a hashmap but `SipHash` (default hasher) performance is not great
/// when protection against collisions is not required, so either use a vector indexed by
/// an offset + record or [xxHash](https://github.com/Cyan4973/xxHash)
#[derive(Debug, Default)]
struct MessageBuffer {
    buf: HashMap<RecordId, BufItem>,
}

#[derive(Debug)]
enum BufItem {
    /// There is an outstanding request to receive the message but this helper hasn't seen it yet
    Requested(oneshot::Sender<Box<[u8]>>),
    /// Message has been received but nobody requested it yet
    Received(Box<[u8]>),
}

#[derive(Debug)]
struct ReceiveRequest<S> {
    from: Identity,
    step: S,
    record_id: RecordId,
    sender: oneshot::Sender<Box<[u8]>>,
}

impl<S: Step> ReceiveRequest<S> {
    pub fn new(
        from: Identity,
        step: S,
        record_id: RecordId,
        sender: oneshot::Sender<Box<[u8]>>,
    ) -> Self {
        Self {
            from,
            step,
            record_id,
            sender,
        }
    }

    pub fn channel_id(&self) -> ChannelId<S> {
        ChannelId::new(self.from, self.step)
    }
}

#[derive(Debug)]
pub struct Gateway<'a, S, F> {
    identity: Identity,
    fabric: &'a F,
    tx: mpsc::Sender<ReceiveRequest<S>>,
}

#[derive(Debug)]
pub struct Mesh<'a, S, F> {
    fabric: &'a F,
    identity: Identity,
    step: S,
    gateway_tx: mpsc::Sender<ReceiveRequest<S>>,
}

impl <'a, S, F> Mesh<'a, S, F> {
    fn new(fabric: &'a F, channel_id: ChannelId<S>, gateway_tx: mpsc::Sender<ReceiveRequest<S>>) -> Self {
        Self {
            fabric,
            identity: channel_id.identity,
            step: channel_id.step,
            gateway_tx
        }
    }
}

impl <S: Step, F: Fabric<S>> Mesh<'_, S, F> {
    pub async fn send<T: Message>(
        &mut self,
        dest: Identity,
        record_id: RecordId,
        msg: T,
    ) -> Result<(), Error> {
        let channel = self.fabric.get_connection(ChannelId::new(dest, self.step)).await;
        let bytes = serde_json::to_vec(&msg).unwrap().into_boxed_slice();
        let envelope = MessageEnvelope {
            record_id,
            payload: bytes,
        };

        channel.send(envelope).await
    }

    /// Receive a message that is associated with the given record id.
    pub async fn receive<T: Message>(&mut self, source: Identity, record_id: RecordId)
        -> Result<T, Error> {
        let (tx, mut rx) = oneshot::channel();

        self.gateway_tx
            .send(ReceiveRequest { from: source, step: self.step, record_id, sender: tx })
            .await
            .unwrap();

        let payload = rx.await.unwrap();
        let obj: T = serde_json::from_slice(&payload).unwrap();

        Ok(obj)
    }

    /// Returns the unique identity of this helper.
    pub fn identity(&self) -> Identity {
        self.identity
    }
}

impl <'a, S: Step, F: Fabric<S>> Gateway<'a, S, F> {
    pub fn new(identity: Identity, fabric: &'a F) -> Self {
        let (tx, mut receive_rx) = mpsc::channel::<ReceiveRequest<S>>(1);
        let mut message_stream = fabric.message_stream();

        tokio::spawn(async move {
            let mut buf = HashMap::<ChannelId<S>, MessageBuffer>::new();

            loop {
                // Make a random choice what to process next:
                // * Receive and process a control message
                // * Receive a message from another helper
                // * Handle the request to receive a message from another helper
                tokio::select! {
                    Some(receive_request) = receive_rx.recv() => {
                        tracing::trace!("new {:?}", receive_request);
                        buf.entry(receive_request.channel_id())
                           .or_default()
                           .receive_request(receive_request.record_id, receive_request.sender);
                    }
                    Some((channel_id, messages)) = message_stream.next() => {
                        // tracing::trace!("new MessageArrival(from={from_peer:?}, step={step:?}, record={:?}, size={}B)", message_envelope.record_id, message_envelope.payload.len());
                        buf.entry(channel_id)
                           .or_default()
                           .receive_messages(messages);
                    }
                    else => {
                        tracing::debug!("All channels are closed and event loop is terminated");
                        break;
                    }
                }
            }
        }).instrument(tracing::info_span!("gateway_event_loop", identity=?identity));

        Self {
            identity,
            fabric,
            tx
        }
    }

    /// Create or return an existing channel for a given step. Protocols can send messages to
    /// any helper through this channel (see `Mesh` interface for details).
    ///
    /// This method makes no guarantee that the communication channel will actually be established
    /// between this helper and every other one. The actual connection may be created only when
    /// `Mesh::send` or `Mesh::receive` methods are called.
    pub fn get_channel(&self, step: S) -> Mesh<'_, S, F> {
        Mesh::new(&self.fabric, ChannelId::new(self.identity, step), self.tx.clone())
    }
}

impl MessageBuffer {
    /// Process request to receive a message with the given `RecordId`.
    fn receive_request(&mut self, record_id: RecordId, s: oneshot::Sender<Box<[u8]>>) {
        match self.buf.entry(record_id) {
            Entry::Occupied(entry) => match entry.remove() {
                BufItem::Requested(_) => {
                    panic!("More than one request to receive a message for {record_id:?}");
                }
                BufItem::Received(payload) => {
                    s.send(payload).unwrap_or_else(|_| {
                        tracing::warn!("No listener for message {record_id:?}");
                    });
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(BufItem::Requested(s));
            }
        }
    }

    /// Process message that has been received
    fn receive_message(&mut self, msg: MessageEnvelope) {
        match self.buf.entry(msg.record_id) {
            Entry::Occupied(entry) => match entry.remove() {
                BufItem::Requested(s) => {
                    s.send(msg.payload).unwrap_or_else(|_| {
                        tracing::warn!("No listener for message {:?}", msg.record_id);
                    });
                }
                BufItem::Received(_) => {
                    panic!("Duplicate message for the same record {:?}", msg.record_id);
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(BufItem::Received(msg.payload));
            }
        }
    }

    fn receive_messages(&mut self, msgs: Vec<MessageEnvelope>) {
        msgs.into_iter().for_each(|msg| {
            self.receive_message(msg)
        })
    }
}
