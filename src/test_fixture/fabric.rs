use std::collections::hash_map::Entry;
use std::collections::HashMap;

use std::fmt::{Debug, Formatter};

use crate::helpers::fabric::{
    ChannelId, CommunicationChannel, MessageChunks, MessageEnvelope, Network,
};
use crate::helpers::Identity;
use crate::protocol::UniqueStepId;
use async_trait::async_trait;
use futures_util::stream::SelectAll;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;

use crate::helpers;
use crate::helpers::error::Error;
use futures::StreamExt;
use tokio::sync::mpsc;

/// Represents control messages sent between helpers to handle infrastructure requests.
pub(super) enum ControlMessage {
    /// Connection for a step is requested by the peer.
    ConnectionRequest(ChannelId, Receiver<MessageEnvelope>),
}

/// Container for all active helper endpoints
#[derive(Debug)]
pub struct InMemoryNetwork {
    pub endpoints: [Arc<InMemoryEndpoint>; 3],
}

/// Helper endpoint in memory. Capable of opening connections to other helpers and buffering
/// messages it receives from them until someone requests them.
#[derive(Debug)]
pub struct InMemoryEndpoint {
    pub identity: Identity,
    /// Channels that this endpoint is listening to. There are two helper peers for 3 party setting.
    /// For each peer there are multiple channels open, one per query + step.
    channels: Arc<Mutex<Vec<HashMap<UniqueStepId, InMemoryChannel>>>>,
    tx: Sender<ControlMessage>,
    rx: Arc<Mutex<Option<Receiver<MessageChunks>>>>,
    network: Weak<InMemoryNetwork>,
}

/// In memory channel is just a standard mpsc channel.
#[derive(Debug, Clone)]
pub struct InMemoryChannel {
    dest: Identity,
    tx: Sender<MessageEnvelope>,
}

impl InMemoryNetwork {
    #[must_use]
    pub fn new() -> Arc<Self> {
        Arc::new_cyclic(|weak_ptr| {
            let endpoints = Identity::all_variants()
                .map(|i| Arc::new(InMemoryEndpoint::new(i, Weak::clone(weak_ptr))));

            Self { endpoints }
        })
    }
}

impl InMemoryEndpoint {
    /// Creates new instance for a given helper identity.
    ///
    /// # Panics
    /// Panics are not expected
    #[must_use]
    pub fn new(id: Identity, world: Weak<InMemoryNetwork>) -> Self {
        let (tx, mut open_channel_rx) = mpsc::channel(1);
        let (message_stream_tx, message_stream_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            let mut channels = SelectAll::new();
            let mut buf = HashMap::<ChannelId, Vec<MessageEnvelope>>::new();

            loop {
                tokio::select! {
                    Some(control_message) = open_channel_rx.recv() => {
                        match control_message {
                            ControlMessage::ConnectionRequest(channel_id, new_channel_rx) => {
                                channels.push(ReceiverStream::new(new_channel_rx).map(move |msg| (channel_id.clone(), msg)));
                            }
                        }
                    }
                    Some((channel_id, msg)) = channels.next() => {
                        buf.entry(channel_id).or_default().push(msg);
                    }
                    // If there is nothing else to do, try to obtain a permit to move messages
                    // from the buffer to messaging layer. Potentially we might be thrashing
                    // on permits here.
                    Ok(permit) = message_stream_tx.reserve(), if !buf.is_empty() => {
                        // TODO(alex): this is bad and I want to experiment with
                        // Vec<EnumMap<Step, Vec<MessageEnvelope>>, basically using double indirection
                        // identity -> step -> vec of messages. That will require to keep track
                        // of all messages in the buffer in a separate local variable, but makes
                        // fairness easily achievable.
                        let key = buf.keys().next().unwrap().clone();
                        let msgs = buf.remove(&key).unwrap();

                        permit.send((key, msgs));
                    }
                    else => {
                        break;
                    }
                }
            }
        });

        Self {
            identity: id,
            channels: Arc::new(Mutex::new(vec![
                HashMap::default(),
                HashMap::default(),
                HashMap::default(),
            ])),
            tx,
            rx: Arc::new(Mutex::new(Some(message_stream_rx))),
            network: world,
        }
    }
}

#[async_trait]
impl Network for Arc<InMemoryEndpoint> {
    type Channel = InMemoryChannel;
    type MessageStream = ReceiverStream<MessageChunks>;

    async fn get_connection(&self, addr: ChannelId) -> Self::Channel {
        let mut new_rx = None;

        let channel = {
            let mut channels = self.channels.lock().unwrap();
            let peer_channel = &mut channels[addr.identity];

            match peer_channel.entry(addr.step.clone()) {
                Entry::Occupied(entry) => entry.get().clone(),
                Entry::Vacant(entry) => {
                    let (tx, rx) = mpsc::channel(1);
                    let tx = InMemoryChannel {
                        dest: addr.identity,
                        tx,
                    };
                    entry.insert(tx.clone());
                    new_rx = Some(rx);

                    tx
                }
            }
        };

        if let Some(rx) = new_rx {
            self.network.upgrade().unwrap().endpoints[addr.identity]
                .tx
                .send(ControlMessage::ConnectionRequest(
                    ChannelId::new(self.identity, addr.step),
                    rx,
                ))
                .await
                .unwrap();
        }

        channel
    }

    fn message_stream(&self) -> Self::MessageStream {
        let mut rx = self.rx.lock().unwrap();
        if let Some(rx) = rx.take() {
            ReceiverStream::new(rx)
        } else {
            panic!("Message stream has been consumed already");
        }
    }
}

#[async_trait]
impl CommunicationChannel for InMemoryChannel {
    async fn send(&self, msg: MessageEnvelope) -> helpers::Result<()> {
        self.tx
            .send(msg)
            .await
            .map_err(|e| Error::send_error(self.dest, e))
    }
}

impl Debug for ControlMessage {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlMessage::ConnectionRequest(channel, step) => {
                write!(f, "ConnectionRequest(from={:?}, step={:?})", channel, step)
            }
        }
    }
}
