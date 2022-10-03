use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::convert::identity;
use std::fmt::{Debug, Formatter};
use std::ops::Index;
use std::sync::{Arc, Mutex, Weak};
use enum_map::{EnumArray, EnumMap};
use tokio::sync::mpsc::{Receiver, Sender};
use tokio_stream::wrappers::ReceiverStream;
use crate::helpers::fabric::{ChannelId, CommunicationChannel, Fabric, MessageChunks, MessageEnvelope};
use crate::helpers::Identity;
use crate::protocol::Step;
use async_trait::async_trait;
use futures_util::stream::SelectAll;
use rand_core::RngCore;
use tokio::sync::mpsc;
use crate::helpers;
use crate::helpers::error::Error;
use futures::StreamExt;
use rand::Rng;

/// Represents control messages sent between helpers to handle infrastructure requests.
pub(super) enum ControlMessage<S> {
    /// Connection for step S is requested by the peer
    ConnectionRequest(ChannelId<S>, Receiver<MessageEnvelope>),
}

#[derive(Debug)]
struct InMemoryMesh<S> {
    endpoints: [InMemoryEndpoint<S>; 3]
}


#[derive(Debug)]
struct InMemoryEndpoint<S> {
    id: Identity,

    // Channels that this endpoint is listening to. There are two helper peers for 3 party setting.
    // For each peer there are multiple channels open, one per query + step.
    channels: Arc<Mutex<Vec<HashMap<S, InMemoryChannel>>>>,
    tx: Sender<ControlMessage<S>>,
    rx: Arc<Mutex<Option<Receiver<MessageChunks>>>>,
    world: Weak<InMemoryMesh<S>>,
}

/// In memory channel is just a standard mpsc channel.
#[derive(Debug, Clone)]
struct InMemoryChannel {
    dest: Identity,
    tx: Sender<MessageEnvelope>
}

impl <S: Step> InMemoryMesh<S> {

    pub fn new<R: RngCore + Clone + Send + 'static>(mut r: R) -> Arc<Self> {
        let world = Arc::new_cyclic(|weak_ptr| {
            let endpoints = Identity::all_variants()
                .map(|i| InMemoryEndpoint::new(i, weak_ptr.clone(), r.clone()));

            Self { endpoints }
        });

        world
    }
}

impl <S: Step> InMemoryEndpoint<S> {
    pub fn new<R: RngCore + Send + 'static>(id: Identity, world: Weak<InMemoryMesh<S>>, mut r: R) -> Self {
        let (tx, mut open_channel_rx) = mpsc::channel(1);
        let (message_stream_tx, message_stream_rx) = mpsc::channel(1);

        tokio::spawn(async move {
            let mut channels = SelectAll::new();
            let mut buf = HashMap::<ChannelId<S>, MessageChunks>::new();

            loop {
                tokio::select! {
                    Some(control_message) = open_channel_rx.recv() => {
                        match control_message {
                            ControlMessage::ConnectionRequest(channel_id, new_channel_rx) => {
                                channels.push(ReceiverStream::new(new_channel_rx).map(move |msg| (channel_id, msg)));
                            }
                        }
                    }
                    Some((channel_id, msg)) = channels.next() => {
                        buf.entry(channel_id).or_default().push(msg)
                    }
                    // If there is nothing else to do, try to obtain a permit to move messages
                    // from the buffer to messaging layer. Potentially we might be thrashing
                    // on permits here.
                    Ok(permit) = message_stream_tx.reserve(), if buf.len() > 0 => {
                        let random_v = r.gen_range(0..buf.len());
                        let key = *buf.keys().skip(random_v).take(1).last().unwrap();
                        let msgs = buf.remove(&key).unwrap();

                        permit.send(msgs);
                    }
                    else => {
                        break;
                    }
                }
            }
        });

        Self {
            id,
            channels: Arc::new(Mutex::new(vec![HashMap::default(), HashMap::default(), HashMap::default()])),
            tx,
            rx: Arc::new(Mutex::new(Some(message_stream_rx))),
            world,
        }
    }
}


#[async_trait]
impl <S: Step + EnumArray<Option<InMemoryChannel>> + Sync> Fabric<S> for InMemoryEndpoint<S> {
    type Channel = InMemoryChannel;
    type MessageStream = ReceiverStream<MessageChunks>;

    async fn get_connection(&self, addr: ChannelId<S>) -> Self::Channel {
        let mut new_rx = None;

        let channel = {
            let mut channels = self.channels.lock().unwrap();
            let mut peer_channel = &mut channels[addr.identity];

            match peer_channel.entry(addr.step) {
                Entry::Occupied(entry) => {
                    entry.get().clone()
                }
                Entry::Vacant(entry) => {
                    let (tx, rx) = tokio::sync::mpsc::channel(1);
                    let tx = InMemoryChannel { dest: addr.identity, tx };
                    entry.insert(tx.clone());
                    new_rx = Some(rx);

                    tx
                }
            }
        };

        if let Some(rx) = new_rx {
            self.world.upgrade().unwrap().endpoints[addr.identity].tx
                .send(ControlMessage::ConnectionRequest(ChannelId::new(self.id, addr.step), rx)).await.unwrap();
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
        self.tx.send(msg).await.map_err(|e| Error::send_error(self.dest, e))
    }
}

impl<S: Step> Debug for ControlMessage<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlMessage::ConnectionRequest(channel, step) => {
                write!(f, "ConnectionRequest(from={:?}, step={:?})", channel, step)
            }
        }
    }
}

