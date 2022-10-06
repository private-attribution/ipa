use crate::helpers::error::Error;
use crate::helpers::Identity;
use crate::protocol::{RecordId, Step};
use async_trait::async_trait;
use futures::Stream;
use std::fmt::{Debug, Formatter};

/// Combination of helper identity and step that uniquely identifies a single channel of communication
/// between two helpers.
#[derive(Copy, Clone, Eq, PartialEq, Hash)]
pub struct ChannelId<S> {
    pub identity: Identity,
    pub step: S,
}

#[derive(Debug)]
pub struct MessageEnvelope {
    pub record_id: RecordId,
    pub payload: Box<[u8]>,
}

pub type MessageChunks<S> = (ChannelId<S>, Vec<MessageEnvelope>);

#[async_trait]
pub trait Fabric<S: Step>: Sync {
    type Channel: CommunicationChannel;
    type MessageStream: Stream<Item = MessageChunks<S>> + Send + Unpin + 'static;

    async fn get_connection(&self, addr: ChannelId<S>) -> Self::Channel;
    fn message_stream(&self) -> Self::MessageStream;
}

#[async_trait]
pub trait CommunicationChannel {
    async fn send(&self, msg: MessageEnvelope) -> Result<(), Error>;
}

impl<S: Step> ChannelId<S> {
    pub fn new(identity: Identity, step: S) -> Self {
        Self { identity, step }
    }
}

impl<S: Debug> Debug for ChannelId<S> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel[peer={:?},step={:?}]", self.identity, self.step)
    }
}
