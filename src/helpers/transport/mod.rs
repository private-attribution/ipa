mod error;
pub mod query;

use std::borrow::Borrow;
pub use error::Error as TransportError;

use crate::protocol::Step;
use crate::{helpers::HelperIdentity, protocol::QueryId};
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
    StepData(QueryId, Step, Vec<u8>),
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

/// The source of the command, i.e. where it came from. Some may arrive from helper peers, others
/// may come directly from the clients
#[derive(Debug)]
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
    type CommandStream: Stream<Item = CommandEnvelope> + Send + Unpin;

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
        destination: &HelperIdentity,
        command: C,
    ) -> Result<(), TransportError>;
}
