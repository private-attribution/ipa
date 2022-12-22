mod error;

pub use error::Error as TransportError;

use crate::protocol::Step;
use crate::{helpers::HelperIdentity, protocol::QueryId};
use async_trait::async_trait;
use futures::Stream;

pub trait TransportCommandData {
    type RespData;
    fn name() -> &'static str;
    fn respond(self, query_id: QueryId, data: Self::RespData) -> Result<(), TransportError>;
}

#[derive(Debug)]
pub struct NetworkEventData {
    pub query_id: QueryId,
    pub step: Step,
    pub payload: Vec<u8>,
}

impl NetworkEventData {
    #[must_use]
    pub fn new(query_id: QueryId, step: Step, payload: Vec<u8>) -> Self {
        Self {
            query_id,
            step,
            payload,
        }
    }
}

impl TransportCommandData for NetworkEventData {
    type RespData = ();
    fn name() -> &'static str {
        "NetworkEvent"
    }
    fn respond(self, _: QueryId, _: Self::RespData) -> Result<(), TransportError> {
        Ok(())
    }
}

#[derive(Debug)]
pub enum TransportCommand {
    // `Administration` Commands
    /// TODO: none for now
    // `Query` Commands
    // message via `subscribe_to_query` method
    NetworkEvent(NetworkEventData),
}

/// Users of a [`Transport`] must subscribe to a specific type of command, and so must pass this
/// type as argument to the `subscribe` function
#[allow(dead_code)] // will use this soon
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SubscriptionType {
    /// Commands for managing queries
    Administration,
    /// Commands intended for a running query
    Query(QueryId),
}

#[derive(Debug)]
pub struct CommandEnvelope {
    pub origin: HelperIdentity,
    pub payload: TransportCommand,
}

#[async_trait]

pub trait Transport: Send + Sync + 'static {
    type CommandStream: Stream<Item = CommandEnvelope> + Send + Unpin;

    /// To be called by an entity which will handle the events as indicated by the
    /// [`SubscriptionType`]. There should be only 1 subscriber per type.
    /// # Panics
    /// May panic if attempt to subscribe to the same [`SubscriptionType`] twice
    async fn subscribe(&self, subscription_type: SubscriptionType) -> Self::CommandStream;

    /// To be called when an entity wants to send commands to the `Transport`.
    async fn send(
        &self,
        destination: &HelperIdentity,
        command: TransportCommand,
    ) -> Result<(), TransportError>;
}
