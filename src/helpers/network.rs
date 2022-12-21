#![allow(dead_code)] // will use these soon

use crate::{
    helpers::{
        transport::{NetworkEventData, SubscriptionType, Transport, TransportCommand},
        Error, HelperIdentity, Role,
    },
    protocol::{QueryId, Step},
};
use futures::{Stream, StreamExt};
use std::fmt::{Debug, Formatter};

/// Combination of helper role and step that uniquely identifies a single channel of communication
/// between two helpers.
#[derive(Clone, Eq, PartialEq, Hash)]
pub struct ChannelId {
    pub role: Role,
    pub step: Step,
}

impl ChannelId {
    #[must_use]
    pub fn new(role: Role, step: Step) -> Self {
        Self { role, step }
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel[{:?},{:?}]", self.role, self.step)
    }
}

pub type MessageChunks = (ChannelId, Vec<u8>);

/// Given any implementation of [`Transport`], a `Network` is able to send and receive
/// [`MessageChunks`] for a specific query id. The [`Transport`] will receive `NetworkEvents`
/// containing the `MessageChunks`
pub struct Network<T> {
    transport: T,
    query_id: QueryId,
    roles_to_helpers: [HelperIdentity; 3],
}

impl<T: Transport> Network<T> {
    pub fn new(transport: T, query_id: QueryId, roles_to_helpers: [HelperIdentity; 3]) -> Self {
        Self {
            transport,
            query_id,
            roles_to_helpers,
        }
    }

    /// sends a [`NetworkEvent`] containing [`MessageChunks`] on the underlying [`Transport`]
    /// # Errors
    /// if `message_chunks` fail to be delivered
    /// # Panics
    /// if `roles_to_helpers` does not have all 3 roles
    pub async fn send(&self, message_chunks: MessageChunks) -> Result<(), Error> {
        let role = message_chunks.0.role;
        let destination = &self.roles_to_helpers[role];
        self.transport
            .send(
                destination,
                TransportCommand::NetworkEvent(NetworkEventData {
                    query_id: self.query_id,
                    message_chunks,
                }),
            )
            .await
            .map_err(Error::from)
    }

    /// returns a [`Stream`] of [`MessageChunks`]s from the underlying [`Transport`]
    /// # Panics
    /// if called more than once during the execution of a query.
    pub fn recv_stream(&self) -> impl Stream<Item = MessageChunks> {
        let query_id = self.query_id;
        let query_command_stream = self.transport.subscribe(SubscriptionType::Query(query_id));

        #[allow(unreachable_patterns)] // there will be more commands in the future
        query_command_stream.map(move |command| match command {
            TransportCommand::NetworkEvent(NetworkEventData { message_chunks, .. }) => {
                message_chunks
            }
            other_command => panic!(
                "received unexpected command {other_command:?} for query id {}",
                query_id.as_ref()
            ),
        })
    }
}
