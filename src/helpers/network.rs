#![allow(dead_code)] // will use these soon

use crate::helpers::transport::CommandOrigin;
use crate::helpers::{MessagePayload, RoleAssignment};
use crate::protocol::RecordId;
use crate::{
    helpers::{
        transport::{SubscriptionType, Transport, TransportCommand},
        Error, Role,
    },
    protocol::{QueryId, Step},
    sync::{Arc, Mutex},
};
use futures::{Stream, StreamExt};
use std::collections::HashMap;
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
/// [`MessageChunks`] for a specific query id. The [`Transport`] will receive `StepData`
/// containing the `MessageChunks`
pub struct Network<T> {
    transport: T,
    query_id: QueryId,
    roles: RoleAssignment,
    send_offset_tracker: Arc<Mutex<HashMap<ChannelId, u32>>>,
}

impl<T: Transport> Network<T> {
    #[must_use]
    pub fn new(transport: T, query_id: QueryId, roles: RoleAssignment) -> Self {
        Self {
            transport,
            query_id,
            roles,
            send_offset_tracker: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Increments the offset for a given [`ChannelId`], or sets it to 0 if there's no current
    /// entry. Optionally compares new offset with expected. Returns the previous value
    fn inc_and_ensure_offset(
        offset_tracker: &mut HashMap<ChannelId, u32>,
        query_id: QueryId,
        channel_id: &ChannelId,
        ensure_next: Option<u32>,
    ) -> u32 {
        let last_seen = offset_tracker.entry(channel_id.clone()).or_default();
        match ensure_next {
            Some(next_seen) if *last_seen != next_seen => panic!(
                "out-of-order delivery of data for query:{}, role:{}, step:{}: expected index {}, but found {next_seen}",
                query_id.as_ref(),
                channel_id.role.as_ref(),
                channel_id.step.as_ref(),
                *last_seen,
            ),
            _ => {
                let prev = *last_seen;
                *last_seen += 1;
                prev
            }
        }
    }

    /// sends a [`StepData`] command containing [`MessageChunks`] on the underlying [`Transport`]
    /// # Errors
    /// if `message_chunks` fail to be delivered
    /// # Panics
    /// if mutex lock is poisoned
    pub async fn send(&self, message_chunks: MessageChunks) -> Result<(), Error> {
        let (channel, payload) = message_chunks;
        let destination = self.roles.identity(channel.role);
        let send_offset = Self::inc_and_ensure_offset(
            &mut self.send_offset_tracker.lock().unwrap(),
            self.query_id,
            &channel,
            None,
        );
        self.transport
            .send(
                destination,
                TransportCommand::StepData {
                    query_id: self.query_id,
                    step: channel.step,
                    payload,
                    offset: send_offset,
                },
            )
            .await?;
        Ok(())
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
        let mut recv_offset_tracker = HashMap::new();

        query_command_stream.map(move |envelope| match envelope.payload {
            TransportCommand::StepData { query_id, step, payload, offset } => {
                debug_assert!(query_id == self_query_id);

                let CommandOrigin::Helper(identity) = &envelope.origin else {
                    panic!("Message origin is incorrect: expected it to be from a helper, got {:?}", &envelope.origin);
                };
                let origin_role = assignment.role(*identity);
                let channel_id = ChannelId::new(origin_role, step);

                Self::inc_and_ensure_offset(&mut recv_offset_tracker, self_query_id, &channel_id, Some(offset));

                (channel_id, payload)
            }
            TransportCommand::Query(_) => panic!(
                "received unexpected command {envelope:?} for query id {}",
                self_query_id.as_ref()
            ),
        })
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        helpers::{CommandEnvelope, HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        test_fixture::transport::InMemoryNetwork,
    };
    use futures::stream::StreamExt;

    async fn assert_successful_send(
        this_network: &Network<impl Transport>,
        dest_stream: &mut (impl Stream<Item = CommandEnvelope> + Unpin),
        expected_query_id: QueryId,
        message_chunks: &MessageChunks,
        expected_offset: u32,
    ) {
        let res = this_network.send(message_chunks.clone()).await;
        assert!(res.is_ok(), "{res:?}");
        {
            let send_offset_tracker = this_network.send_offset_tracker.lock().unwrap();
            let next_offset = *send_offset_tracker.get(&message_chunks.0).unwrap();
            assert_eq!(next_offset, expected_offset + 1);
        }
        let command = dest_stream.next().await.unwrap();
        assert_eq!(
            command.origin,
            CommandOrigin::Helper(this_network.transport.identity())
        );
        if let TransportCommand::StepData {
            query_id,
            step,
            payload,
            offset,
        } = command.payload
        {
            assert_eq!(query_id, expected_query_id);
            assert_eq!(step, message_chunks.0.step.clone());
            assert_eq!(payload, message_chunks.1.clone());
            assert_eq!(offset, expected_offset);
        } else {
            panic!("expected command to be `StepData`, but it was {command:?}")
        }
    }

    #[tokio::test]
    async fn successfully_sends() {
        let roles = RoleAssignment::new(HelperIdentity::make_three());
        let h1_identity = roles.identity(Role::H1);
        let h2_identity = roles.identity(Role::H2);

        let message_chunks = (
            ChannelId::new(
                roles.role(h1_identity),
                Step::default().narrow("successfully-sends"),
            ),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );
        let expected_query_id = QueryId;

        let transports = InMemoryNetwork::default();
        let h2_transport = transports.transport(h2_identity).unwrap();
        let h2_network = Network::new(h2_transport, expected_query_id, roles.clone());
        let h1_transport = transports.transport(h1_identity).unwrap();
        let mut h1_stream = h1_transport
            .subscribe(SubscriptionType::Query(expected_query_id))
            .await;

        for i in 0..10 {
            assert_successful_send(
                &h2_network,
                &mut h1_stream,
                expected_query_id,
                &message_chunks,
                i,
            )
            .await;
        }
    }

    #[tokio::test]
    #[should_panic(expected = "out-of-order delivery of data for")] // just the prefix
    async fn rejects_bad_offset() {
        let expected_query_id = QueryId;
        let expected_role = Role::H2;
        let expected_step = Step::default().narrow("rejects-bad-offset");
        let expected_payload = vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES];

        let transports = InMemoryNetwork::default();
        let identities = transports.helper_identities();
        let h1_identity = identities[Role::H1];
        let h2_identity = identities[Role::H2];

        let h1_transport = transports.transport(h1_identity).unwrap();
        let h1_network = Network::new(
            h1_transport,
            expected_query_id,
            RoleAssignment::new(identities),
        );
        let mut message_chunks_stream = h1_network.recv_stream().await;

        let h2_transport = transports.transport(h2_identity).unwrap();
        let command = TransportCommand::StepData {
            query_id: expected_query_id,
            step: expected_step.clone(),
            payload: expected_payload.clone(),
            offset: 0,
        };
        h2_transport.send(h1_identity, command).await.unwrap();
        assert_eq!(
            (
                ChannelId::new(expected_role, expected_step.clone()),
                expected_payload.clone()
            ),
            message_chunks_stream.next().await.unwrap()
        );

        // send with offset == 0 again; this time should panic
        let command = TransportCommand::StepData {
            query_id: expected_query_id,
            step: expected_step.clone(),
            payload: expected_payload.clone(),
            offset: 0,
        };
        h2_transport.send(h1_identity, command).await.unwrap();
        message_chunks_stream.next().await.unwrap();
    }
}
