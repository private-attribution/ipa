use crate::{
    helpers::{network::ChannelId, MessagePayload, MESSAGE_PAYLOAD_SIZE_BYTES},
    helpers::messaging::TotalRecords,
    protocol::RecordId,
};
use std::{collections::hash_map::Entry, num::NonZeroUsize};
use std::collections::HashMap;
use std::fmt::Debug;
use tokio::sync::oneshot;

#[derive(Debug)]
struct ReceiveChannel {
    total_records: TotalRecords,
    received_records: usize,
    items: HashMap<RecordId, ReceiveBufItem>,
}

/// Local buffer for messages that are either awaiting requests to receive them or requests
/// that are pending message reception.
/// TODO: Right now it is backed by a hashmap but `SipHash` (default hasher) performance is not great
/// when protection against collisions is not required, so either use a vector indexed by
/// an offset + record or [xxHash](https://github.com/Cyan4973/xxHash)
#[derive(Debug, Default)]
#[allow(clippy::module_name_repetitions)]
pub struct ReceiveBuffer {
    inner: HashMap<ChannelId, ReceiveChannel>,
    record_ids: HashMap<ChannelId, RecordId>,
}

#[derive(Debug)]
enum ReceiveBufItem {
    /// There is an outstanding request to receive the message but this helper hasn't seen it yet
    Requested(oneshot::Sender<MessagePayload>),
    /// Message has been received but nobody requested it yet
    Received(MessagePayload),
}

impl ReceiveBuffer {
    fn update_record_count(&mut self, channel_id: ChannelId) {
        let channel = self.inner.get_mut(&channel_id).expect("update_record_count called for invalid channel");
        channel.received_records += 1;
        let total_records = if let TotalRecords::Specified(value) = channel.total_records {
            value
        } else {
            return;
        };
        if NonZeroUsize::new(channel.received_records) == Some(total_records) {
            assert!(channel.items.is_empty());
            tracing::trace!("close rx {:?}", &channel_id);
            self.inner.remove(&channel_id);
            self.record_ids.remove(&channel_id);
        }
    }

    /// Process request to receive a message with the given `RecordId`.
    pub fn receive_request(
        &mut self,
        channel_id: ChannelId,
        record_id: RecordId,
        sender: oneshot::Sender<MessagePayload>,
        total_records: NonZeroUsize,
    ) {
        //let total_records = channel_id.total_records.expect("can't receive without a known total record count");
        let channel = self.inner.entry(channel_id.clone()).or_insert_with(|| {
            tracing::trace!("create rx channel for rx request {:?}", &channel_id);
            ReceiveChannel {
                total_records: TotalRecords::Specified(total_records),
                received_records: 0,
                items: Default::default(),
            }
        });
        match channel.items.entry(record_id) {
            Entry::Occupied(entry) => match entry.remove() {
                ReceiveBufItem::Requested(_) => {
                    panic!("More than one request to receive a message for {record_id:?}");
                }
                ReceiveBufItem::Received(payload) => {
                    self.update_record_count(channel_id.clone());
                    sender.send(payload).unwrap_or_else(|_| {
                        tracing::warn!("No listener for message {record_id:?}");
                    });
                }
            },
            Entry::Vacant(entry) => {
                entry.insert(ReceiveBufItem::Requested(sender));
            }
        }
    }

    /// Process messages that has been received. It assumes messages arriving in order, so first
    /// chunk will belong to range of records [0..chunk.len()), second chunk [chunk.len()..2*chunk.len())
    /// etc. It does not require all chunks to be of the same size, this assumption is baked in
    /// send buffers.
    pub fn receive_messages(&mut self, channel_id: &ChannelId, messages: &[u8]) {
        // TODO: this is probably wrong. Need to maintain total count as
        // unknown until we see a receive request.
        //let total_records = channel_id.total_records.expect("can't receive without a known total record count");

        let offset = self
            .record_ids
            .entry(channel_id.clone())
            .or_insert_with(|| RecordId::from(0_u32));
        *offset += 1;
        // TODO: need to pre-increment and drop this reference so we can
        // call update_record_count below.  Can we do better?
        let offset = *offset;

        for msg in messages.chunks(MESSAGE_PAYLOAD_SIZE_BYTES) {
            let payload = msg.try_into().unwrap();
            let channel = self
                .inner
                .entry(channel_id.clone())
                .or_insert_with(|| {
                    tracing::trace!("create rx channel for rx msg {:?}", &channel_id);
                    ReceiveChannel {
                        total_records: TotalRecords::Unspecified,
                        received_records: 0,
                        items: Default::default(),
                    }
                });
            match channel.items.entry(offset - 1)
            {
                Entry::Occupied(entry) => match entry.remove() {
                    ReceiveBufItem::Requested(s) => {
                        self.update_record_count(channel_id.clone());
                        s.send(payload).unwrap_or_else(|_| {
                            tracing::warn!("No listener for message {offset:?}");
                        });
                    }
                    ReceiveBufItem::Received(_) => {
                        panic!("Duplicate message for the same record {offset:?}")
                    }
                },
                Entry::Vacant(entry) => {
                    entry.insert(ReceiveBufItem::Received(payload));
                }
            };
        }
    }

    pub fn open_channels(&self) -> usize {
        assert_eq!(self.inner.len(), self.record_ids.len());
        self.inner.len()
    }

    #[cfg(debug_assertions)]
    pub(in crate::helpers) fn waiting(&self) -> super::waiting::WaitingTasks {
        use super::waiting::WaitingTasks;

        let mut tasks = HashMap::new();
        for (channel, receive_items) in &self.inner {
            let mut vec = receive_items
                .items.iter()
                .filter_map(|(record_id, item)| match item {
                    ReceiveBufItem::Requested(_) => Some(u32::from(*record_id)),
                    ReceiveBufItem::Received(_) => None,
                })
                .collect::<Vec<_>>();

            if !vec.is_empty() {
                vec.sort_unstable();
                tasks.insert(channel, vec);
            }
        }

        WaitingTasks::new(tasks)
    }
}
