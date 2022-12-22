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
use crate::helpers::RoleAssignment;

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
    roles: RoleAssignment
}

impl<T: Transport> Network<T> {
    pub fn new(transport: T, query_id: QueryId, roles: RoleAssignment) -> Self {
        Self {
            transport,
            query_id,
            roles,
        }
    }

    /// sends a [`NetworkEvent`] containing [`MessageChunks`] on the underlying [`Transport`]
    /// # Errors
    /// if `message_chunks` fail to be delivered
    /// # Panics
    /// if `roles_to_helpers` does not have all 3 roles
    pub async fn send(&self, message_chunks: MessageChunks) -> Result<(), Error> {
        let (channel, payload) = message_chunks;
        let destination = self.roles.identity(channel.role);

        self.transport
            .send(
                destination,
                TransportCommand::NetworkEvent(NetworkEventData {
                    query_id: self.query_id,
                    step: channel.step,
                    payload
                }),
            )
            .await
            .map_err(Error::from)
    }

    /// returns a [`Stream`] of [`MessageChunks`]s from the underlying [`Transport`]
    /// # Panics
    /// if called more than once during the execution of a query.
    pub async fn recv_stream(&self) -> impl Stream<Item = MessageChunks> {
        let self_query_id = self.query_id;
        let query_command_stream = self.transport.subscribe(SubscriptionType::Query(self_query_id)).await;


        #[allow(unreachable_patterns)] // there will be more commands in the future
        query_command_stream.map(move |command| match command {
            TransportCommand::NetworkEvent(NetworkEventData { query_id, step, payload }) => {
                debug_assert!(query_id == self_query_id);

                let origin_role = Role::H1;
                let channel_id = ChannelId::new(origin_role, step);

                (channel_id, payload)
                // message_chunks
            }
            other_command => panic!(
                "received unexpected command {other_command:?} for query id {}",
                self_query_id.as_ref()
            ),
        })
    }
}
