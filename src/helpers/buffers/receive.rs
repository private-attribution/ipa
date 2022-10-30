use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use crate::protocol::RecordId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use tokio::sync::oneshot;

/// Local buffer for messages that are either awaiting requests to receive them or requests
/// that are pending message reception.
/// TODO: Right now it is backed by a hashmap but `SipHash` (default hasher) performance is not great
/// when protection against collisions is not required, so either use a vector indexed by
/// an offset + record or [xxHash](https://github.com/Cyan4973/xxHash)
#[derive(Debug, Default)]
pub(in crate::helpers) struct ReceiveBuffer {
    inner: HashMap<ChannelId, HashMap<RecordId, ReceiveBufItem>>,
}

#[derive(Debug)]
enum ReceiveBufItem {
    /// There is an outstanding request to receive the message but this helper hasn't seen it yet
    Requested(oneshot::Sender<Box<[u8]>>),
    /// Message has been received but nobody requested it yet
    Received(Box<[u8]>),
}

impl ReceiveBuffer {
    /// Process request to receive a message with the given `RecordId`.
    pub fn receive_request(
        &mut self,
        channel_id: ChannelId,
        record_id: RecordId,
        sender: oneshot::Sender<Box<[u8]>>,
    ) {
        match self.inner.entry(channel_id).or_default().entry(record_id) {
            Entry::Occupied(entry) => match entry.remove() {
                ReceiveBufItem::Requested(_) => {
                    panic!("More than one request to receive a message for {record_id:?}");
                }
                ReceiveBufItem::Received(payload) => {
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

    /// Process message that has been received
    pub fn receive_messages(&mut self, channel_id: &ChannelId, messages: Vec<MessageEnvelope>) {
        for msg in messages {
            match self
                .inner
                .entry(channel_id.clone())
                .or_default()
                .entry(msg.record_id)
            {
                Entry::Occupied(entry) => match entry.remove() {
                    ReceiveBufItem::Requested(s) => {
                        s.send(msg.payload).unwrap_or_else(|_| {
                            tracing::warn!("No listener for message {:?}", msg.record_id);
                        });
                    }
                    ReceiveBufItem::Received(_) => {
                        panic!("Duplicate message for the same record {:?}", msg.record_id);
                    }
                },
                Entry::Vacant(entry) => {
                    entry.insert(ReceiveBufItem::Received(msg.payload));
                }
            }
        }
    }
}
