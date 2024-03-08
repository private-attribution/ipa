use std::marker::PhantomData;

use dashmap::{mapref::entry::Entry, DashMap};
use futures::Stream;

use crate::{
    helpers::{buffers::UnorderedReceiver, ChannelId, Error, Message, Transport, TransportImpl},
    protocol::RecordId,
};

/// Receiving end end of the gateway channel.
pub struct ReceivingEnd<M: Message> {
    channel_id: ChannelId,
    unordered_rx: UR,
    _phantom: PhantomData<M>,
}

/// Receiving channels, indexed by (role, step).
#[derive(Default)]
pub(super) struct GatewayReceivers {
    pub(super) inner: DashMap<ChannelId, UR>,
}

pub(super) type UR = UnorderedReceiver<
    <TransportImpl as Transport>::RecordsStream,
    <<TransportImpl as Transport>::RecordsStream as Stream>::Item,
>;

impl<M: Message> ReceivingEnd<M> {
    pub(super) fn new(channel_id: ChannelId, rx: UR) -> Self {
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
    //#[tracing::instrument(level = "trace", "receive", skip_all, fields(i = %record_id, from = ?self.channel_id.role, gate = ?self.channel_id.gate.to_string()))]
    pub async fn receive(&self, record_id: RecordId) -> Result<M, Error> {
        self.unordered_rx
            .recv::<M, _>(record_id)
            .await
            .map_err(|e| Error::ReceiveError {
                source: self.channel_id.role,
                step: self.channel_id.gate.to_string(),
                inner: Box::new(e),
            })
    }
}

impl GatewayReceivers {
    pub fn get_or_create<F: FnOnce() -> UR>(&self, channel_id: &ChannelId, ctr: F) -> UR {
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
