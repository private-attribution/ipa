//!
//! This module contains implementations and traits that enable protocols to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC protocols to do.
//!
use crate::{
    bits::Serializable,
    ff::Field,
    helpers::{
        buffers::{ReceiveBuffer, SendBuffer, SendBufferConfig},
        network::{ChannelId, MessageEnvelope, Network},
        time::Timer,
        transport::Transport,
        Error, MessagePayload, Role, MESSAGE_PAYLOAD_SIZE_BYTES,
    },
    protocol::{RecordId, Step},
    task::JoinHandle,
    telemetry::{labels::STEP, metrics::RECORDS_SENT},
};
use futures::StreamExt;
use futures_util::stream::FuturesUnordered;
use generic_array::GenericArray;
use std::fmt::{Debug, Formatter};
use std::num::NonZeroUsize;
use std::time::Duration;
use tinyvec::array_vec;
use tracing::Instrument;
use typenum::Unsigned;

use ::tokio::sync::{mpsc, oneshot};
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

/// Trait for messages sent between helpers. Everything needs to be serializable and safe to send.
pub trait Message: Debug + Send + Serializable + 'static {}

/// Any field value can be send as a message
impl<F: Field> Message for F {}

/// Entry point to the messaging layer managing communication channels for protocols and provides
/// the ability to send and receive messages from helper peers. Protocols request communication
/// channels to be open by calling `get_channel`, after that it is possible to send messages
/// through the channel end and request a given message type from helper peer.
///
/// Gateways are generic over `Network` meaning they can operate on top of in-memory communication
/// channels and real network.
///
/// ### Implementation details
/// Gateway, when created, runs an event loop in a dedicated tokio task that pulls the messages
/// from the networking layer and attempts to fulfil the outstanding requests to receive them.
/// If `receive` method on the channel has never been called, it puts the message to the local
/// buffer and keeps it there until such request is made by the protocol.
/// TODO: limit the size of the buffer and only pull messages when there is enough capacity
#[derive(Debug)]
pub struct Gateway {
    /// Sender end of the channel to send requests to receive messages from peers.
    tx: mpsc::Sender<ReceiveRequest>,
    envelope_tx: mpsc::Sender<SendRequest>,
    control_handle: JoinHandle<()>,
    role: Role,
}

pub(super) type SendRequest = (ChannelId, MessageEnvelope);

#[derive(Clone, Copy, Debug)]
pub enum TotalRecords {
    Unspecified,
    Specified(NonZeroUsize),

    /// Total number of records is not well-determined. When the record ID is
    /// counting solved_bits attempts. The total record count for solved_bits
    /// depends on the number of failures.
    ///
    /// The purpose of this is to waive the warning that there is a known
    /// number of records when creating a channel. If the warning is firing
    /// and the total number of records is knowable, prefer to specify it
    /// rather than use this to waive the warning.
    Indeterminate,
}

impl TotalRecords {
    #[must_use]
    pub fn is_unspecified(&self) -> bool {
        matches!(self, &TotalRecords::Unspecified)
    }

    #[must_use]
    pub fn is_indeterminate(&self) -> bool {
        matches!(self, &TotalRecords::Indeterminate)
    }
}

impl From<usize> for TotalRecords {
    fn from(value: usize) -> Self {
        match NonZeroUsize::new(value) {
            Some(v) => TotalRecords::Specified(v),
            None => TotalRecords::Unspecified,
        }
    }
}

/// Channel end
#[derive(Debug)]
pub struct Mesh<'a, 'b> {
    gateway: &'a Gateway,
    step: &'b Step,
    total_records: TotalRecords,
}

pub(super) struct ReceiveRequest {
    pub channel_id: ChannelId,
    pub record_id: RecordId,
    pub sender: oneshot::Sender<MessagePayload>,
}

impl Mesh<'_, '_> {
    /// Send a given message to the destination. This method will not return until the message
    /// is delivered to the `Network`.
    ///
    /// # Errors
    /// Returns an error if it fails to send the message or if there is a serialization error.
    ///
    /// # Panics
    /// If the context has a total record count set and the `record_id` to be sent is out of range.
    pub async fn send<T: Message>(
        &self,
        dest: Role,
        record_id: RecordId,
        msg: T,
    ) -> Result<(), Error> {
        if T::Size::USIZE > MESSAGE_PAYLOAD_SIZE_BYTES {
            Err(Error::serialization_error::<String>(record_id,
                                                     self.step,
                                                     format!("Message {msg:?} exceeds the maximum size allowed: {MESSAGE_PAYLOAD_SIZE_BYTES}"))
            )?;
        }

        if let TotalRecords::Specified(count) = self.total_records {
            assert!(
                usize::from(record_id) < usize::from(count),
                "record ID {:?} is out of range for {:?} (expected {:?} records)",
                record_id,
                self.step,
                self.total_records,
            );
        }

        let mut payload = array_vec![0; MESSAGE_PAYLOAD_SIZE_BYTES];
        let mut data = GenericArray::default();
        msg.serialize(&mut data);
        payload[..data.len()].copy_from_slice(&data);

        let envelope = MessageEnvelope { record_id, payload };

        self.gateway
            .send(ChannelId::new(dest, self.step.clone()), envelope)
            .await
    }

    /// Receive a message that is associated with the given record id.
    ///
    /// # Errors
    /// Returns an error if it fails to receive the message or if a deserialization error occurred
    ///
    /// # Panics
    /// If the context has a total record count set and the `record_id` to be received is out of range.
    pub async fn receive<T: Message>(&self, source: Role, record_id: RecordId) -> Result<T, Error> {
        if let TotalRecords::Specified(count) = self.total_records {
            assert!(
                usize::from(record_id) < usize::from(count),
                "record ID {:?} is out of range for {:?} (expected {:?} records)",
                record_id,
                self.step,
                self.total_records
            );
        }

        let payload = self
            .gateway
            .receive(ChannelId::new(source, self.step.clone()), record_id)
            .await?;

        let g = GenericArray::from_slice(&payload[..T::Size::USIZE]);
        let obj = T::deserialize(g);

        Ok(obj)
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// Configuration for send buffers. See `SendBufferConfig` for more details
    pub send_buffer_config: SendBufferConfig,
    /// The maximum number of items that can be outstanding for sending.
    pub send_outstanding: usize,
    /// The maximum number of items that can be outstanding for receiving.
    pub recv_outstanding: usize,
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            send_outstanding: 16,
            recv_outstanding: 16,
            send_buffer_config: SendBufferConfig::default(),
        }
    }
}

impl Gateway {
    pub async fn new<T: Transport>(role: Role, network: Network<T>, config: GatewayConfig) -> Self {
        let (recv_tx, mut recv_rx) = mpsc::channel::<ReceiveRequest>(config.recv_outstanding);
        let (send_tx, mut send_rx) = mpsc::channel::<SendRequest>(config.send_outstanding);
        let mut message_stream = network.recv_stream().await;

        let control_handle = tokio::spawn(async move {
            const INTERVAL: Duration = Duration::from_secs(3);

            let mut receive_buf = ReceiveBuffer::default();
            let mut send_buf = SendBuffer::new(config.send_buffer_config);
            let mut pending_sends = FuturesUnordered::new();
            let sleep = Timer::new(INTERVAL);
            ::tokio::pin!(sleep);

            loop {
                // Make a random choice what to process next:
                // * Receive a message from another helper
                // * Handle the request to receive a message from another helper
                // * Send a message
                ::tokio::select! {
                    Some(receive_request) = recv_rx.recv() => {
                        tracing::trace!("new {:?}", receive_request);
                        receive_buf.receive_request(receive_request.channel_id, receive_request.record_id, receive_request.sender);
                    }
                    Some((channel_id, messages)) = message_stream.next() => {
                        tracing::trace!("received {} bytes from {:?}", messages.len(), channel_id);
                        receive_buf.receive_messages(&channel_id, &messages);
                    }
                    Some((channel_id, envelope)) = send_rx.recv(), if pending_sends.is_empty() => {
                        tracing::trace!("new SendRequest({:?})", (&channel_id, &envelope));
                        metrics::increment_counter!(RECORDS_SENT, STEP => channel_id.step.as_ref().to_string());
                        if let Some(buf_to_send) = send_buf.push(&channel_id, &envelope) {
                            tracing::trace!("sending {} bytes to {:?}", buf_to_send.len(), &channel_id);
                            pending_sends.push(async { network
                                .send((channel_id, buf_to_send))
                                .await
                                .expect("Failed to send data to the network");
                            });
                        }
                    }
                    Some(_) = &mut pending_sends.next() => {
                        pending_sends.clear();
                    }
                    _ = &mut sleep => {
                        #[cfg(debug_assertions)]
                        print_state(role, &send_buf, &receive_buf);
                    }
                    else => {
                        tracing::debug!("All channels are closed and event loop is terminated");
                        break;
                    }
                }

                // reset the timer on every action
                sleep.as_mut().reset();
            }
        }.instrument(tracing::info_span!("gateway_loop", role=role.as_static_str()).or_current()));

        Self {
            tx: recv_tx,
            envelope_tx: send_tx,
            control_handle,
            role,
        }
    }

    /// Create or return an existing channel for a given step. Protocols can send messages to
    /// any helper through this channel (see `Mesh` interface for details).
    ///
    /// This method makes no guarantee that the communication channel will actually be established
    /// between this helper and every other one. The actual connection may be created only when
    /// `Mesh::send` or `Mesh::receive` methods are called.
    ///
    /// ## Panics
    /// In `debug_assertions` config, if the `ALREADY_WARNED` mutex is poisoned.
    #[must_use]
    pub fn mesh<'a, 'b>(&'a self, step: &'b Step, total_records: TotalRecords) -> Mesh<'a, 'b> {
        debug_assert!(!total_records.is_unspecified());
        Mesh {
            gateway: self,
            step,
            total_records,
        }
    }

    /// Join the control loop task and wait until its completed.
    ///
    /// ## Panics
    /// if control loop task panicked, the panic will be propagated to this thread
    #[cfg(not(feature = "shuttle"))]
    pub async fn join(self) {
        self.control_handle
            .await
            .map_err(|e| {
                if e.is_panic() {
                    std::panic::resume_unwind(e.into_panic())
                } else {
                    "Task cancelled".to_string()
                }
            })
            .unwrap();
    }

    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }

    async fn receive(
        &self,
        channel_id: ChannelId,
        record_id: RecordId,
    ) -> Result<MessagePayload, Error> {
        let (tx, rx) = oneshot::channel();
        self.tx
            .send(ReceiveRequest {
                channel_id: channel_id.clone(),
                record_id,
                sender: tx,
            })
            .await?;

        rx.await
            .map_err(|e| Error::receive_error(channel_id.role, e))
    }

    async fn send(&self, id: ChannelId, env: MessageEnvelope) -> Result<(), Error> {
        Ok(self.envelope_tx.send((id, env)).await?)
    }
}

#[cfg(feature = "shuttle")]
impl Drop for Gateway {
    fn drop(&mut self) {
        self.control_handle.abort();
    }
}

impl Debug for ReceiveRequest {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ReceiveRequest({:?}, {:?})",
            self.channel_id, self.record_id
        )
    }
}

#[cfg(debug_assertions)]
fn print_state(role: Role, send_buf: &SendBuffer, receive_buf: &ReceiveBuffer) {
    let send_tasks_waiting = send_buf.waiting();
    let receive_tasks_waiting = receive_buf.waiting();
    if !send_tasks_waiting.is_empty() || !receive_tasks_waiting.is_empty() {
        tracing::error!(
            "List of tasks pending completion on {role:?}:\
        \nwaiting to send: {send_tasks_waiting:?},\
        \nwaiting to receive: {receive_tasks_waiting:?}"
        );
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::ff::Fp31;
    use crate::helpers::messaging::TotalRecords;
    use crate::helpers::Role;
    use crate::protocol::context::Context;
    use crate::protocol::{RecordId, Step};
    use crate::test_fixture::{TestWorld, TestWorldConfig};
    use std::num::NonZeroUsize;

    #[tokio::test]
    pub async fn handles_reordering() {
        let mut config = TestWorldConfig::default();
        config.gateway_config.send_buffer_config.items_in_batch = NonZeroUsize::new(1).unwrap(); // Send every record
        config.gateway_config.send_buffer_config.batch_count = NonZeroUsize::new(3).unwrap(); // keep 3 at a time

        let world = Box::leak(Box::new(TestWorld::new_with(config).await));
        let contexts = world.contexts::<Fp31>();
        let sender_ctx = contexts[0].narrow("reordering-test").set_total_records(2);
        let recv_ctx = contexts[1].narrow("reordering-test").set_total_records(2);

        // send record 1 first and wait for confirmation before sending record 0.
        // when gateway received record 0 it triggers flush so it must make sure record 1 is also
        // sent (same batch or different does not matter here)
        tokio::spawn(async move {
            let channel = sender_ctx.mesh();
            channel
                .send(Role::H2, RecordId::from(1), Fp31::from(1_u128))
                .await
                .unwrap();
            channel
                .send(Role::H2, RecordId::from(0), Fp31::from(0_u128))
                .await
                .unwrap();
        });

        // intentionally ignoring record 0 here
        let v: Fp31 = recv_ctx
            .mesh()
            .receive(Role::H1, RecordId::from(1))
            .await
            .unwrap();
        assert_eq!(Fp31::from(1_u128), v);
    }

    #[tokio::test]
    #[should_panic(expected = "Duplicate send for index 1 on channel")]
    async fn duplicate_message() {
        let world = TestWorld::new().await;
        let (v1, v2) = (Fp31::from(1u128), Fp31::from(2u128));
        let peer = Role::H2;
        let record_id = 1.into();
        let step = Step::default();
        let total_records = TotalRecords::from(2);
        let channel = &world.gateway(Role::H1).mesh(&step, total_records);

        channel.send(peer, record_id, v1).await.unwrap();
        channel.send(peer, record_id, v2).await.unwrap();

        world.join().await;
    }
}
