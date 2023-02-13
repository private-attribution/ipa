pub mod query;

mod bytearrstream;
mod error;

pub use bytearrstream::{AlignedByteArrStream, ByteArrStream};
pub use error::Error as TransportError;

use crate::{
    helpers::HelperIdentity,
    protocol::{QueryId, Step},
};
use async_trait::async_trait;
use futures::Stream;

#[derive(Debug)]
pub enum TransportCommand {
    // `Administration` Commands
    Query(query::QueryCommand),

    // `Query` Commands
    /// Query/step data received from a helper peer.
    /// TODO: this is really bad for performance, once we have channel per step all the way
    /// from gateway to network, this definition should be (QueryId, Step, Stream<Item = Vec<u8>>) instead
    StepData {
        query_id: QueryId,
        step: Step,
        payload: Vec<u8>,
        // TODO: we shouldn't require an offset here
        offset: u32,
    },
}

impl TransportCommand {
    /// TODO: why do we need this? can `#[derive(Debug)]` be enough?
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Query(query_command) => query_command.name(),
            Self::StepData { .. } => "StepData",
        }
    }

    #[must_use]
    pub fn query_id(&self) -> Option<QueryId> {
        match self {
            Self::Query(query_command) => query_command.query_id(),
            Self::StepData { query_id, .. } => Some(*query_id),
        }
    }
}

/// Users of a [`Transport`] must subscribe to a specific type of command, and so must pass this
/// type as argument to the `subscribe` function
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub enum SubscriptionType {
    /// Commands for managing queries
    QueryManagement,
    /// Commands intended for a running query
    Query(QueryId),
}

impl From<&TransportCommand> for SubscriptionType {
    fn from(value: &TransportCommand) -> Self {
        match value {
            TransportCommand::Query(_) => SubscriptionType::QueryManagement,
            TransportCommand::StepData { query_id, .. } => SubscriptionType::Query(*query_id),
        }
    }
}

/// The source of the command, i.e. where it came from. Some may arrive from helper peers, others
/// may come directly from the clients
#[derive(Debug, Eq, PartialEq)]
pub enum CommandOrigin {
    Helper(HelperIdentity),
    Other,
}

/// Wrapper around `TransportCommand` that indicates the origin of it.
#[derive(Debug)]
pub struct CommandEnvelope {
    pub origin: CommandOrigin,
    pub payload: TransportCommand,
}

/// Represents the transport layer of the IPA network. Allows layers above to subscribe for events
/// arriving from helper peers or other parties (clients) and also reliably deliver messages using
/// `send` method.
#[async_trait]
pub trait Transport: Send + Sync + 'static {
    type CommandStream: Stream<Item = CommandEnvelope> + Send + Sync + Unpin;

    /// Returns the identity of the helper that runs this transport
    fn identity(&self) -> HelperIdentity;

    /// To be called by an entity which will handle the events as indicated by the
    /// [`SubscriptionType`]. There should be only 1 subscriber per type.
    /// # Panics
    /// May panic if attempt to subscribe to the same [`SubscriptionType`] twice
    async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream;

    /// To be called when an entity wants to send commands to the `Transport`.
    async fn send<C: Send + Into<TransportCommand>>(
        &self,
        destination: HelperIdentity,
        command: C,
    ) -> Result<(), TransportError>;
}
