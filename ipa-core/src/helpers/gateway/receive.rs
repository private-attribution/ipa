use std::{
    marker::PhantomData,
    pin::Pin,
    task::{Context, Poll},
};

use bytes::Bytes;
use dashmap::{DashMap, mapref::entry::Entry};
use futures::Stream;
use pin_project::pin_project;

use crate::{
    error::BoxError,
    helpers::{
        ChannelId, Error, HelperChannelId, LogErrors, Message, MpcMessage, Role, ShardChannelId,
        ShardTransportImpl, Transport, TransportIdentity,
        buffers::{UnorderedReceiver, UnorderedReceiverError},
        gateway::transport::RoleResolvingTransport,
        transport::SingleRecordStream,
    },
    protocol::RecordId,
    sync::{Arc, Mutex},
};

/// Receiving end of the MPC gateway channel.
/// I tried to make it generic and work for both MPC and Shard connectors, but ran into
/// "implementation of `S` is not general enough" issue on the client side (reveal). It may be another
/// occurrence of [`gat`] issue
///
/// [`gat`]: https://github.com/rust-lang/rust/issues/100013
pub struct MpcReceivingEnd<M> {
    channel_id: HelperChannelId,
    unordered_rx: UR,
    _phantom: PhantomData<fn() -> M>,
}

#[pin_project]
pub struct ShardReceivingEnd<M: Message> {
    pub(super) channel_id: ShardChannelId,
    #[pin]
    pub(super) rx: SingleRecordStream<M, ShardReceiveStream>,
}

/// Receiving channels, indexed by (role, step).
pub(super) struct GatewayReceivers<I, S> {
    pub(super) inner: DashMap<ChannelId<I>, S>,
}

pub type UR = UnorderedReceiver<
    LogErrors<<RoleResolvingTransport as Transport>::RecordsStream, Bytes, BoxError>,
    Vec<u8>,
>;

/// Stream of records received from a peer shard.
#[derive(Clone)]
pub struct ShardReceiveStream(
    /// Using a mutex here may not be necessary - there is always a single caller that polls it,
    /// and there may be an observer from stall detection that wants to know the state of it.
    /// There could be a better way to share the state and make sure the owning reference is stored
    /// inside the map of receivers.
    pub(super) Arc<Mutex<<ShardTransportImpl as Transport>::RecordsStream>>,
);

impl<M: MpcMessage> MpcReceivingEnd<M> {
    pub(super) fn new(channel_id: HelperChannelId, rx: UR) -> Self {
        Self {
            channel_id,
            unordered_rx: rx,
            _phantom: PhantomData,
        }
    }

    /// Receive message associated with the given record id. This method does not return until
    /// message is actually received and deserialized.
    ///
    /// ## Errors
    /// Returns an error if receiving fails
    ///
    /// ## Panics
    /// This will panic if message size does not fit into 8 bytes and it somehow got serialized
    /// and sent to this helper.
    #[tracing::instrument(level = "trace", "receive", skip_all, fields(i = %record_id, from = ?self.channel_id.peer, gate = ?self.channel_id.gate.as_ref()))]
    pub async fn receive(&self, record_id: RecordId) -> Result<M, Error<Role>> {
        self.unordered_rx
            .recv::<M, _>(record_id)
            .await
            .map_err(|e| match e {
                UnorderedReceiverError::DeserializeFailed(inner) => Error::DeserializeFailed {
                    channel_id: self.channel_id.clone(),
                    inner,
                },
                UnorderedReceiverError::EndOfStream(inner) => Error::EndOfStream {
                    channel_id: self.channel_id.clone(),
                    inner,
                },
            })
    }
}

impl<M: Message> Stream for ShardReceivingEnd<M> {
    type Item = Result<M, crate::error::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.project().rx.poll_next(cx)
    }
}

impl<I: TransportIdentity, S> Default for GatewayReceivers<I, S> {
    fn default() -> Self {
        Self {
            inner: DashMap::default(),
        }
    }
}

impl<I: TransportIdentity, S: Clone> GatewayReceivers<I, S> {
    pub fn get_or_create<F: FnOnce() -> S>(&self, channel_id: &ChannelId<I>, ctr: F) -> S {
        // TODO: raw entry API if it becomes available to avoid cloning the key
        match self.inner.entry(channel_id.clone()) {
            Entry::Occupied(entry) => entry.get().clone(),
            Entry::Vacant(entry) => {
                let stream = ctr();
                entry.insert(stream.clone());

                stream
            }
        }
    }
}

impl Stream for ShardReceiveStream {
    type Item = <<ShardTransportImpl as Transport>::RecordsStream as Stream>::Item;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Pin::new(self.0.lock().unwrap()).as_mut().poll_next(cx)
    }
}
