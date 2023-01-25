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
        let mut recv_offset_tracker = HashMap::new();

        query_command_stream.map(move |envelope| match envelope.payload {
            TransportCommand::StepData { query_id, step, payload, offset } => {
                debug_assert!(query_id == self_query_id);

                let CommandOrigin::Helper(identity) = &envelope.origin else {
                    panic!("Message origin is incorrect: expected it to be from a helper, got {:?}", &envelope.origin);
                };
                let origin_role = assignment.role(identity);
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
    use crate::helpers::{
        CommandEnvelope, HelperIdentity, TransportError, MESSAGE_PAYLOAD_SIZE_BYTES,
    };
    use async_trait::async_trait;
    use futures::stream::StreamExt;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    pub struct NoopTransport {
        identity: HelperIdentity,
        queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
        queries_outbox: Arc<Mutex<[Option<TransportCommand>; 3]>>,
    }

    impl NoopTransport {
        pub fn new(identity: HelperIdentity) -> Arc<Self> {
            Arc::new(Self {
                identity,
                queries: Arc::new(Mutex::new(HashMap::new())),
                queries_outbox: Arc::new(Mutex::new([None, None, None])),
            })
        }

        pub async fn send_to_self(&self, command: CommandEnvelope) -> Result<(), TransportError> {
            match command {
                CommandEnvelope {
                    origin: CommandOrigin::Helper(identity),
                    payload:
                        TransportCommand::StepData {
                            query_id,
                            step,
                            payload,
                            offset,
                        },
                } => {
                    let sender = {
                        let queries = self.queries.lock().unwrap();
                        queries
                            .get(&query_id)
                            .ok_or(TransportError::SendFailed {
                                command_name: Some("StepData"),
                                query_id: Some(query_id),
                                inner: "no sender for query_id found".into(),
                            })?
                            .clone()
                    };

                    Ok(sender
                        .send(CommandEnvelope {
                            origin: CommandOrigin::Helper(identity),
                            payload: TransportCommand::StepData {
                                query_id,
                                step,
                                payload,
                                offset,
                            },
                        })
                        .await
                        .map_err(|err| mpsc::error::SendError(err.0.payload))?)
                }
                other => panic!("unexpected command {other:?}"),
            }
        }

        pub fn retrieve_from_outbox(
            &self,
            destination: HelperIdentity,
        ) -> Option<TransportCommand> {
            let mut outbox = self.queries_outbox.lock().unwrap();
            (*outbox)[destination].take()
        }
    }

    #[async_trait]
    impl Transport for Arc<NoopTransport> {
        type CommandStream = ReceiverStream<CommandEnvelope>;

        fn identity(&self) -> HelperIdentity {
            self.identity
        }

        async fn subscribe(&self, subscription: SubscriptionType) -> Self::CommandStream {
            match subscription {
                SubscriptionType::QueryManagement => unimplemented!(),
                SubscriptionType::Query(query_id) => {
                    let (tx, rx) = mpsc::channel(1);
                    assert!(
                        self.queries.lock().unwrap().insert(query_id, tx).is_none(),
                        "entry existed for query_id {}",
                        query_id.as_ref()
                    );
                    ReceiverStream::new(rx)
                }
            }
        }

        async fn send<C: Send + Into<TransportCommand>>(
            &self,
            destination: HelperIdentity,
            command: C,
        ) -> Result<(), TransportError> {
            let mut outbox = self.queries_outbox.lock().unwrap();
            let target = &mut (*outbox)[destination];
            target.replace(command.into()).map_or(Ok(()), |c| {
                Err(TransportError::SendFailed {
                    command_name: Some(c.name()),
                    query_id: c.query_id(),
                    inner: format!("entry already existed in outbox for target {destination:?}")
                        .into(),
                })
            })
        }
    }

    async fn assert_successful_send(
        network: &Network<Arc<NoopTransport>>,
        roles: &RoleAssignment,
        expected_query_id: QueryId,
        message_chunks: &MessageChunks,
        expected_offset: u32,
    ) {
        let res = network.send(message_chunks.clone()).await;
        assert!(res.is_ok(), "{res:?}");
        {
            let send_offset_tracker = network.send_offset_tracker.lock().unwrap();
            let next_offset = send_offset_tracker.get(&message_chunks.0).copied();
            assert_eq!(next_offset, Some(expected_offset + 1));
        }
        let destination = roles.identity(message_chunks.0.role);
        let command = network
            .transport
            .retrieve_from_outbox(destination)
            .unwrap_or_else(|| {
                panic!("command should have been sent to destination {destination:?}")
            });
        if let TransportCommand::StepData {
            query_id,
            step,
            payload,
            offset,
        } = command
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
        let this_role = Role::H2;
        let message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("successfully-sends")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );
        let roles = RoleAssignment::new(HelperIdentity::make_three());

        let noop_transport = NoopTransport::new(roles.identity(this_role));
        let network = Network::new(Arc::clone(&noop_transport), QueryId, roles.clone());
        for i in 0..10 {
            assert_successful_send(&network, &roles, QueryId, &message_chunks, i).await;
        }
    }

    fn step_data_envelope(
        origin: HelperIdentity,
        query_id: QueryId,
        message_chunks: &MessageChunks,
        offset: u32,
    ) -> CommandEnvelope {
        CommandEnvelope {
            origin: CommandOrigin::Helper(origin),
            payload: TransportCommand::StepData {
                query_id,
                step: message_chunks.0.step.clone(),
                payload: message_chunks.1.clone(),
                offset,
            },
        }
    }

    #[tokio::test]
    async fn successfully_receives() {
        let this_role = Role::H2;
        let expected_message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("successfully-receives")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );
        let roles = RoleAssignment::new(HelperIdentity::make_three());
        let noop_transport = NoopTransport::new(roles.identity(this_role));
        let network = Network::new(noop_transport, QueryId, roles.clone());
        let mut message_chunks_stream = network.recv_stream().await;
        let command = step_data_envelope(
            roles.identity(expected_message_chunks.0.role),
            QueryId,
            &expected_message_chunks,
            0,
        );
        network.transport.send_to_self(command).await.unwrap();
        let message_chunks = message_chunks_stream.next().await;
        assert_eq!(message_chunks, Some(expected_message_chunks));
    }

    #[tokio::test]
    async fn fails_if_not_subscribed() {
        let roles = RoleAssignment::new(HelperIdentity::make_three());
        let message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("no-subscribe")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );
        let command = step_data_envelope(
            roles.identity(message_chunks.0.role),
            QueryId,
            &message_chunks,
            0,
        );
        let noop_transport = NoopTransport::new(roles.identity(Role::H2));
        let network = Network::new(noop_transport, QueryId, roles);

        // missing:
        // let mut message_chunks_stream = network.recv_stream().await;

        let sent = network.transport.send_to_self(command).await;
        assert!(matches!(sent, Err(TransportError::SendFailed { .. })));
    }

    #[tokio::test]
    #[should_panic(expected = "out-of-order delivery of data for")] // just the prefix
    async fn rejects_bad_offset() {
        let this_role = Role::H2;
        let message_chunks = (
            ChannelId::new(Role::H1, Step::default().narrow("rejects-bad-offset")),
            vec![0u8; MESSAGE_PAYLOAD_SIZE_BYTES],
        );
        let roles = RoleAssignment::new(HelperIdentity::make_three());

        let noop_transport = NoopTransport::new(roles.identity(this_role));
        let network = Network::new(Arc::clone(&noop_transport), QueryId, roles.clone());
        let mut message_chunks_stream = network.recv_stream().await;

        let command = step_data_envelope(
            roles.identity(message_chunks.0.role),
            QueryId,
            &message_chunks,
            0,
        );
        network.transport.send_to_self(command).await.unwrap();
        message_chunks_stream.next().await.unwrap();

        // send with offset == 0 again; this time should panic
        let command = step_data_envelope(
            roles.identity(message_chunks.0.role),
            QueryId,
            &message_chunks,
            0,
        );
        network.transport.send_to_self(command).await.unwrap();
        message_chunks_stream.next().await.unwrap();
    }
}
