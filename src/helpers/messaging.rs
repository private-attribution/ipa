//!
//! This module contains implementations and traits that enable protocols to communicate with
//! each other. In order for helpers to send messages, they need to know the destination. In some
//! cases this might be the exact address of helper host/instance (for example IP address), but
//! in many situations MPC helpers simply need to be able to send messages to the
//! corresponding helper without needing to know the exact location - this is what this module
//! enables MPC protocols to do.
//!
use crate::{
    helpers::buffers::{ReceiveBuffer, SendBuffer},
    helpers::error::Error,
    helpers::fabric::{ChannelId, MessageEnvelope, Network},
    helpers::Identity,
    protocol::{RecordId, UniqueStepId},
};

use futures::SinkExt;
use futures::StreamExt;
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::{Debug, Formatter};
use crate::field::Int;
use crate::helpers::buffers::SendBufferError;
use std::time::Duration;
use smallvec::{Array, SmallVec, smallvec};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tracing::Instrument;
use crate::field::{DeserializationError, Field};
use crate::helpers::fabric::InlineBuf;

/// Trait for messages sent between helpers
pub trait Message: Debug + Send + Serialize + DeserializeOwned + 'static {
    const BYTES: usize;

    /// TODO: return result
    fn deserialize(buf: &mut [u8]) -> Self;
    fn serialize(self, buf: &mut [u8]);
}

impl <F: Field> Message for F {
    const BYTES: usize = F::Integer::BYTES;

    fn deserialize(buf: &mut [u8]) -> Self {
        <F as Field>::deserialize(buf).unwrap()
    }

    fn serialize(self, buf: &mut [u8]) {
        <F as Field>::serialize(&self, buf);
    }
}

// impl<T> Message for T where T: Debug + Send + Serialize + DeserializeOwned + 'static {}

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
pub struct Gateway<N> {
    role: Identity,
    /// TODO: no need to keep it here if we're happy with its interface
    _network: N,
    /// Sender end of the channel to send requests to receive messages from peers.
    receive_request_tx: mpsc::Sender<ReceiveRequest>,
    envelope_tx: mpsc::Sender<(
        ChannelId,
        MessageEnvelope,
        oneshot::Sender<SendRequestStatus>,
    )>,
    control_handle: JoinHandle<()>,
}

#[derive(Debug)]
pub(super) enum SendRequestStatus {
    Accepted,
    Rejected(SendBufferError),
}

/// Channel end
#[derive(Debug)]
pub struct Mesh<'a, 'b, N> {
    gateway: &'a Gateway<N>,
    step: &'b UniqueStepId,
    role: Identity,
}

pub(super) struct ReceiveRequest {
    pub channel_id: ChannelId,
    pub record_id: RecordId,
    pub sender: oneshot::Sender<InlineBuf>,
}

impl<N: Network> Mesh<'_, '_, N> {
    /// Send a given message to the destination. This method will not return until the message
    /// is delivered to the `Network`.
    ///
    /// # Errors
    /// Returns an error if it fails to send the message or if there is a serialization error.
    pub async fn send<T: Message>(
        &self,
        dest: Identity,
        record_id: RecordId,
        msg: T,
    ) -> Result<(), Error> {
        let mut payload = smallvec![0; 8];
        assert!(T::BYTES < 32, "Infra is not ready to send large messages yet");
        msg.serialize(&mut payload);
        assert!(!payload.spilled());

        // let bytes = serde_json::to_vec(&msg)
        //     .map_err(|e| Error::serialization_error(record_id, self.step, e))?
        //     .into_boxed_slice();

        let envelope = MessageEnvelope {
            record_id,
            payload
        };

        self.gateway
            .send(&ChannelId::new(dest, self.step.clone()), envelope)
            .await
    }

    /// Receive a message that is associated with the given record id.
    ///
    /// # Errors
    /// Returns an error if it fails to receive the message or if a deserialization error occurred
    pub async fn receive<T: Message>(
        &self,
        source: Identity,
        record_id: RecordId,
    ) -> Result<T, Error> {
        let mut payload = self
            .gateway
            .receive(ChannelId::new(source, self.step.clone()), record_id)
            .await?;

        // TODO error handling
        Ok(<T as Message>::deserialize(&mut payload))

        // let obj: T = serde_json::from_slice(&payload)
        //     .map_err(|e| Error::serialization_error(record_id, self.step, e))?;

        // Ok(obj)
    }

    /// Returns the unique identity of this helper.
    #[must_use]
    pub fn identity(&self) -> Identity {
        self.role
    }
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// Maximum number of items to keep inside the buffer before flushing it to network.
    /// Note that this buffer is per channel, so setting it to 10 does not imply that every
    /// 10 messages sent trigger a network request.
    pub send_buffer_capacity: u32,

    /// The wait time for the gateway before flushing buffers to network if there is no activity
    /// from the protocols.
    /// To make forward progress, we periodically check if the system is stalled
    /// if nothing happens for long period of time, we try to unblock it by flushing
    /// the data that remains inside buffers.
    ///
    /// Increasing this interval leads to higher latencies. Setting it low increases the chance
    /// of flushing buffers that are half-full and underutilizing the network.
    pub flush_interval: Duration,
}

impl<N: Network> Gateway<N> {
    pub fn new(role: Identity, network: N, config: GatewayConfig) -> Self {
        let (tx, mut receive_rx) = mpsc::channel::<ReceiveRequest>(1);
        let (envelope_tx, mut envelope_rx) = mpsc::channel::<(
            ChannelId,
            MessageEnvelope,
            oneshot::Sender<SendRequestStatus>,
        )>(1);
        let mut message_stream = network.recv_stream();
        let mut network_sink = network.sink();

        let control_handle = tokio::spawn(async move {
            let mut receive_buf = ReceiveBuffer::default();
            let mut send_buf = SendBuffer::new(config.send_buffer_capacity);

            let sleep = tokio::time::sleep(config.flush_interval);
            tokio::pin!(sleep);

            loop {
                // Make a random choice what to process next:
                // * Receive a message from another helper
                // * Handle the request to receive a message from another helper
                // * If send buffer is full, send it down
                tokio::select! {
                    Some(receive_request) = receive_rx.recv() => {
                        tracing::trace!("new {:?}", receive_request);
                        receive_buf.receive_request(receive_request.channel_id, receive_request.record_id, receive_request.sender);
                    }
                    Some((channel_id, messages)) = message_stream.next() => {
                        tracing::trace!("received {} message(s) from {:?}", messages.len(), channel_id);
                        receive_buf.receive_messages(&channel_id, messages);
                    }
                    Some((channel_id, msg, status_tx)) = envelope_rx.recv() => {
                        // New send request - attempt to add it to the send buffer.
                        // If buffer is full, flush it down to network layer
                        let record_id = msg.record_id;
                        tracing::trace!("new request to send message {record_id:?} to {channel_id:?}");
                        let status = match send_buf.push(channel_id.clone(), msg) {
                            Ok(maybe_buf) => {
                                if let Some(buf_to_send) = maybe_buf {
                                    tracing::trace!("{channel_id:?} send buffer is full ({} messages)", buf_to_send.len());
                                    network_sink.send((channel_id, buf_to_send)).await
                                        .expect("Failed to send data to the network");
                                }

                                SendRequestStatus::Accepted
                            }
                            Err(error) => {
                                tracing::warn!("Failed to put message with {record_id:?} to the send buffer {channel_id:?}: {error:?}");
                                SendRequestStatus::Rejected(error)
                            }
                        };

                        // report the send status back to the protocol
                        status_tx.send(status).expect("Failed to report send status");
                    }
                    _ = &mut sleep, if send_buf.len() > 0 => {
                        // TODO this is dead wrong, remove it
                        let (channel_id, buf_to_send) = send_buf.remove_random();
                        tracing::trace!("Nothing happened in {:?}, flushing the send buffer {channel_id:?} ({} messages)",
                            config.flush_interval,
                            buf_to_send.len());
                        network_sink.send((channel_id, buf_to_send)).await
                            .expect("Failed to send data to the network");
                    }
                    else => {
                        tracing::debug!("All channels are closed and event loop is terminated");
                        break;
                    }
                }

                // reset the timer as we processed something
                sleep.as_mut().reset(Instant::now() + config.flush_interval);
            }
        }.instrument(tracing::info_span!("gateway_loop", identity=?role)));

        Self {
            role,
            _network: network,
            receive_request_tx: tx,
            envelope_tx,
            control_handle,
        }
    }

    /// Create or return an existing channel for a given step. Protocols can send messages to
    /// any helper through this channel (see `Mesh` interface for details).
    ///
    /// This method makes no guarantee that the communication channel will actually be established
    /// between this helper and every other one. The actual connection may be created only when
    /// `Mesh::send` or `Mesh::receive` methods are called.
    pub fn mesh<'a, 'b>(&'a self, step: &'b UniqueStepId) -> Mesh<'a, 'b, N> {
        Mesh {
            gateway: self,
            role: self.role,
            step,
        }
    }

    async fn receive(
        &self,
        channel_id: ChannelId,
        record_id: RecordId,
    ) -> Result<InlineBuf, Error> {
        let (tx, rx) = oneshot::channel();
        self.receive_request_tx
            .send(ReceiveRequest {
                channel_id: channel_id.clone(),
                record_id,
                sender: tx,
            })
            .await?;

        rx.await
            .map_err(|e| Error::receive_error(channel_id.identity, e))
    }

    /// Sends the given message to the gateway processing loop. If `Gateway` decides that it is
    /// ready to process this message immediately, it will be accepted and `Result::Ok` is returned.
    /// However, that may not be the case. Gateway checks whether `MessageEnvelope::record_id` is
    /// in the valid range of record identifiers. If record id is smaller than the minimum accepted
    /// identifier, this `send` operation is rejected and an error is reported back to the caller.
    /// If record id is larger than the maximum id the acceptable range, `send` is also **rejected**
    /// but this will likely change in the future. Instead of rejecting such messages, `Gateway`
    /// should block such operations until the acceptable window moves and record id becomes valid.
    ///
    /// A valid range size is determined by `GatewayConfig::max_batch_size` configuration parameter.
    /// Once every element inside that range is received by the `Gateway` instance, the whole batch
    /// is flushed to the network layer and acceptable record id window is moved to the right.
    /// That means, that the new window becomes `w_next = w_prev.max..w_prev.max + batch_size`
    ///
    /// This behavior (reject `record_id` > max) is chosen because it is easier to implement and it
    /// makes it easy to debug/unit test MPC protocols. A bug in the implementation may lead to
    /// unit tests flakiness and/or make them never complete. These issues are never easy to debug,
    /// so we may consider this behavior as default for unit testing.
    ///
    /// Once we start processing large amount of data, this behavior will lead to query executions
    /// that never terminate successfully.
    async fn send(&self, id: &ChannelId, env: MessageEnvelope) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.envelope_tx.send((id.clone(), env, tx)).await?;

        let status = rx.await.map_err(|e| Error::receive_error(id.identity, e))?;

        match status {
            SendRequestStatus::Accepted => Ok(()),
            SendRequestStatus::Rejected(reason) => Err(Error::SendError {
                dest: id.identity,
                inner: Box::new(reason),
            }),
        }
    }
}

impl<N> Drop for Gateway<N> {
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
