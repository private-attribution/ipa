#![allow(dead_code)] // will use these soon

use crate::helpers::transport::CommandOrigin;
use crate::helpers::{MessagePayload, RoleAssignment};
use crate::{
    helpers::{
        transport::{SubscriptionType, Transport, TransportCommand},
        Error, Role,
    },
    protocol::{QueryId, RecordId, Step},
};
use futures::{Stream, StreamExt};
use std::fmt::{Debug, Formatter};

#[derive(Debug, PartialEq, Eq)]
pub struct MessageEnvelope {
    pub record_id: RecordId,
    pub payload: MessagePayload,
}

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
        Self {
            role,
            step,
        }
    }
}

impl Debug for ChannelId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "channel[{:?},{:?}]", self.role, self.step)
    }
}

pub type MessageChunks = (ChannelId, Vec<u8>);

/// Given any implementation of [`Transport`], a `Network` is able to send and receive
/// [`MessageChunks`] for a specific query id. The [`Transport`] will receive `StepData`
/// containing the `MessageChunks`
pub struct Network<T> {
    transport: T,
    query_id: QueryId,
    roles: RoleAssignment,
}

impl<T: Transport> Network<T> {
    pub fn new(transport: T, query_id: QueryId, roles: RoleAssignment) -> Self {
        Self {
            transport,
            query_id,
            roles,
        }
    }

    /// sends a `StepData` containing [`MessageChunks`] on the underlying [`Transport`]
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
                TransportCommand::StepData(self.query_id, channel.step, payload),
            )
            .await
            .map_err(Error::from)
    }

    /// returns a [`Stream`] of [`MessageChunks`]s from the underlying [`Transport`]
    /// # Panics
    /// if called more than once during the execution of a query.
    pub async fn recv_stream(&self) -> impl Stream<Item = MessageChunks> {
        let self_query_id = self.query_id;
        let query_command_stream = self
            .transport
            .subscribe(SubscriptionType::Query(self_query_id))
            .await;
        let assignment = self.roles.clone(); // need to move it inside the closure

        query_command_stream.map(move |envelope| match envelope.payload {
            TransportCommand::StepData(query_id, step, payload) => {
                debug_assert!(query_id == self_query_id);

                let CommandOrigin::Helper(identity) = &envelope.origin else {
                    panic!("Message origin is incorrect: expected it to be from a helper, got {:?}", &envelope.origin);
                };
                let origin_role = assignment.role(identity);
                let channel_id = ChannelId::new(origin_role, step);

                (channel_id, payload)
            }
            #[allow(unreachable_patterns)] // there will be more commands in the future
            other_command => panic!(
                "received unexpected command {other_command:?} for query id {}",
                self_query_id.as_ref()
            ),
        })
    }
}
