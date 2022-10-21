use crate::helpers::{error::Error, Identity};
use crate::protocol::{RecordId, UniqueStepId};
use async_trait::async_trait;
use futures::Stream;
use std::fmt::{Debug, Formatter};

/// Combination of helper identity and step that uniquely identifies a single channel of communication
/// between two helpers.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ChannelId {
    pub identity: Identity,
    pub step: UniqueStepId,
}

#[derive(Debug, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub record_id: RecordId,
    pub payload: Box<[u8]>,
}

pub type MessageChunks = (ChannelId, Vec<MessageEnvelope>);

/// Network interface for components that require communication.
#[async_trait]
pub trait Network: Sync {
    /// Type of the channel that is used to send messages to other helpers
    type Channel: CommunicationChannel;
    type MessageStream: Stream<Item = MessageChunks> + Send + Unpin + 'static;

    /// Returns a new connection to be open. `channel_id` indicates the parameters of this
    /// connection (destination peer and step). Once the connection is returned it is immediately
    /// ready for sending messages.
    async fn get_connection(&self, channel_id: ChannelId) -> Self::Channel;

    /// Returns a stream to receive messages that have arrived from other helpers. Note that
    /// some implementations may panic if this method is called more than once.
    fn message_stream(&self) -> Self::MessageStream;
}

#[async_trait]
pub trait CommunicationChannel {
    /// Send a given message
    async fn send(&self, msg: MessageEnvelope) -> Result<(), Error>;
}

impl ChannelId {
    #[must_use]
    pub fn new(identity: Identity, step: UniqueStepId) -> Self {
        Self { identity, step }
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel[peer={:?},step={:?}]", self.identity, self.step)
    }
}
