use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use crate::protocol::RecordId;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::mem;
use std::mem::ManuallyDrop;

use std::ops::Range;
use thiserror::Error;
use tokio::sync::oneshot;

/// Accumulator of records that must be send down to network.
#[derive(Debug)]
struct SendBatch {
    /// The current offset for records that can be accepted by this buffer.
    /// If offset is 0, record identifiers from range 0..`batch_size` are accepted.
    /// If offset is 1, record identifiers from `batch_size`..2*`batch_size` are accepted
    offset: u32,

    /// number of records to accumulate inside the buffer (per channel) before flush.
    batch_size: u32,

    /// The range of valid identifiers currently accepted by the batch.
    accepted_range: Range<RecordId>,

    /// Tracks number of elements in `data`. Must be stored separately because `data` always
    /// contains elements
    len: u32,

    /// Vector of messages with holes. At initialization time it contains `batch_size`
    /// elements, every element is set to `None`. As vector fills in, elements are replaced with
    /// actual messages. Each message takes position in this vector according to its `record_id`
    /// value.
    ///
    /// Here is an example layout for a half-filled batch with `batch_size` = 5 and `offset` = 1.
    /// Note that only record identifiers are shown because other information is irrelevant for this
    /// example.
    /// [None, Record(6), None, Record(8), Record(9)], len = 3
    ///
    /// Once every element in the vec is set, it is considered full and data can be moved
    /// away from it. `SendBatch` guarantees no extra allocations in this case because this vector
    /// is just reinterpreted as `Vec<MessageEnvelope>`.
    ///
    /// If `data` is not full and buffer needs to be flushed to network, a new vector will be
    /// allocated and `data` will be copied element-by-element which is less efficient and therefore
    /// should be avoided if possible
    ///
    /// This implementation guarantees that this vector is sorted according to `MessageEnvelope::record_id`
    data: Vec<Option<MessageEnvelope>>,
}

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
pub(super) struct SendBuffer {
    batch_size: u32,
    initial_offset: u32,
    inner: HashMap<ChannelId, SendBatch>,
}

/// Local buffer for messages that are either awaiting requests to receive them or requests
/// that are pending message reception.
/// TODO: Right now it is backed by a hashmap but `SipHash` (default hasher) performance is not great
/// when protection against collisions is not required, so either use a vector indexed by
/// an offset + record or [xxHash](https://github.com/Cyan4973/xxHash)
#[derive(Debug, Default)]
pub(super) struct ReceiveBuffer {
    inner: HashMap<ChannelId, HashMap<RecordId, ReceiveBufItem>>,
}

#[derive(Debug)]
enum ReceiveBufItem {
    /// There is an outstanding request to receive the message but this helper hasn't seen it yet
    Requested(oneshot::Sender<Box<[u8]>>),
    /// Message has been received but nobody requested it yet
    Received(Box<[u8]>),
}

#[derive(Debug, Error)]
pub(super) enum SendBufferError {
    #[error(
        "Message is out of range (expected record id {record_id:?} to be in {accepted_range:?})"
    )]
    RecordOutOfRange {
        accepted_range: Range<RecordId>,
        record_id: RecordId,
    },
    #[error("Attempt to keep two distinct messages with the same record id {record_id:?}")]
    DuplicateMessage { record_id: RecordId },
}

impl SendBuffer {
    pub(super) fn new(batch_size: u32) -> Self {
        Self::from_batch_and_offset(batch_size, 0)
    }

    fn from_batch_and_offset(batch_size: u32, initial_offset: u32) -> Self {
        assert_ne!(0, batch_size, "Invalid batch size, must be greater than 0");

        Self {
            batch_size,
            initial_offset,
            inner: HashMap::default(),
        }
    }

    pub(super) fn push(
        &mut self,
        channel_id: ChannelId,
        msg: MessageEnvelope,
    ) -> Result<Option<Vec<MessageEnvelope>>, SendBufferError> {
        let batch = match self.inner.entry(channel_id) {
            Entry::Occupied(entry) => {
                let vec = entry.into_mut();
                vec.push(msg)?;

                vec
            }
            Entry::Vacant(entry) => {
                let batch = entry.insert(SendBatch::new(self.initial_offset, self.batch_size));
                batch.push(msg)?;
                batch
            }
        };

        if batch.is_full() {
            Ok(Some(batch.flush()))
        } else {
            Ok(None)
        }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn remove_random(&mut self) -> (ChannelId, Vec<MessageEnvelope>) {
        assert!(self.len() > 0);

        let channel_id = self.inner.keys().next().unwrap().clone();
        let batch = self.inner.remove(&channel_id).unwrap();

        (channel_id, batch.into())
    }
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

impl SendBatch {
    pub fn new(initial_offset: u32, batch_size: u32) -> Self {
        Self {
            offset: initial_offset,
            batch_size,
            accepted_range: RecordId::from(initial_offset * batch_size)
                ..RecordId::from(initial_offset * batch_size + batch_size),
            len: 0,
            data: {
                let batch_size = batch_size as usize;
                let mut data = Vec::with_capacity(batch_size);
                data.resize_with(batch_size, || None);

                data
            },
        }
    }

    pub fn push(&mut self, msg: MessageEnvelope) -> Result<(), SendBufferError> {
        let idx = self.accept_msg(&msg)? as usize;
        if self.data[idx].is_some() {
            Err(SendBufferError::DuplicateMessage {
                record_id: msg.record_id,
            })
        } else {
            self.data[idx] = Some(msg);
            self.len += 1;

            Ok(())
        }
    }

    pub fn is_full(&self) -> bool {
        self.len == self.batch_size
    }

    pub fn flush(&mut self) -> Vec<MessageEnvelope> {
        let offset = self.offset + 1;
        let batch_size = self.batch_size;
        let prev_self = mem::replace(self, Self::new(offset, batch_size));

        prev_self.into()
    }

    fn accept_msg(&self, msg: &MessageEnvelope) -> Result<u32, SendBufferError> {
        if self.accepted_range.contains(&msg.record_id) {
            // safety: safe to subtract unsigned as record_id is greater than min
            Ok(u32::from(msg.record_id) - u32::from(self.accepted_range.start))
        } else {
            Err(SendBufferError::RecordOutOfRange {
                record_id: msg.record_id,
                accepted_range: self.accepted_range.clone(),
            })
        }
    }
}

impl From<SendBatch> for Vec<MessageEnvelope> {
    fn from(value: SendBatch) -> Self {
        // we can safely reinterpret because batch is full
        if value.len == value.batch_size {
            // what we are about to do is unsafe, so it is better to check that we won't cause a UB
            // Note that if the implementation is correct, checking self.len == self.batch_size is enough
            // to prevent undefined behaviour, this is just an extra safety guard
            debug_assert!(value.data.as_slice().iter().all(Option::is_some));

            // safety: Option<T> and T have the same layout as long as Option is Some
            // https://doc.rust-lang.org/std/option/#representation
            // we checked above that all elements inside the vec are set to Some(T) by verifying the len
            unsafe {
                // don't drop the original vector
                let mut data = ManuallyDrop::new(value.data);

                // reinterpret Vec<Option<T>> as Vec<T>
                Vec::from_raw_parts(
                    data.as_mut_ptr().cast::<MessageEnvelope>(),
                    data.len(),
                    data.capacity(),
                )
            }
        } else {
            // batch is not full, a copy is required to flush it
            let mut res = Vec::with_capacity(value.len as usize);

            // the batch is sorted, so traversing it from left to right is enough to keep
            // result sorted as well
            for msg in value.data.into_iter().flatten() {
                res.push(msg);
            }

            res
        }
    }
}

#[cfg(test)]
mod tests {
    mod send_buffer_tests {
        use crate::helpers::buffers::{SendBuffer, SendBufferError};
        use crate::helpers::fabric::{ChannelId, MessageEnvelope};
        use crate::helpers::Identity;
        use crate::protocol::{RecordId, UniqueStepId};
        use rand::seq::SliceRandom;
        use rand::thread_rng;
        use std::cmp::Ordering;

        #[test]
        fn rejects_records_out_of_range() {
            let record_id = RecordId::from(11);
            let accepted_range = RecordId::from(0)..RecordId::from(10);
            let mut buf = SendBuffer::new(10);
            let msg = MessageEnvelope {
                record_id,
                payload: Box::new([]),
            };

            assert!(matches!(
                buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
                Err(SendBufferError::RecordOutOfRange { record_id, accepted_range: range }) if record_id == record_id && range == accepted_range
            ));
        }

        #[test]
        fn offset_is_per_channel() {
            let mut buf = SendBuffer::new(1);
            let c1 = ChannelId::new(Identity::H1, UniqueStepId::default());
            let c2 = ChannelId::new(Identity::H2, UniqueStepId::default());

            let m1 = MessageEnvelope {
                record_id: RecordId::from(0),
                payload: Box::new([]),
            };
            let m2 = MessageEnvelope {
                record_id: RecordId::from(1),
                payload: Box::new([]),
            };

            buf.push(c1.clone(), m1).unwrap();
            buf.push(c1, m2.clone()).unwrap();

            assert!(matches!(
                buf.push(c2, m2),
                Err(SendBufferError::RecordOutOfRange { .. })
            ));
        }

        #[test]
        fn rejects_duplicates() {
            let mut buf = SendBuffer::new(10);
            let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
            let record_id = RecordId::from(3);
            let m1 = MessageEnvelope {
                record_id,
                payload: Box::new([]),
            };
            let m2 = MessageEnvelope {
                record_id,
                payload: Box::new([]),
            };

            assert!(matches!(buf.push(channel.clone(), m1), Ok(None)));
            assert!(matches!(
                buf.push(channel, m2),
                Err(SendBufferError::DuplicateMessage { record_id: _ })
            ));
        }

        #[test]
        fn accepts_records_within_the_valid_range() {
            let mut buf = SendBuffer::new(10);
            let msg = MessageEnvelope {
                record_id: RecordId::from(5),
                payload: Box::new([]),
            };

            assert!(matches!(
                buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
                Ok(None)
            ));
        }

        #[test]
        fn accepts_records_from_next_range_after_flushing() {
            let mut buf = SendBuffer::new(1);
            let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
            let next_msg = MessageEnvelope {
                record_id: RecordId::from(1),
                payload: Box::new([]),
            };
            let this_msg = MessageEnvelope {
                record_id: RecordId::from(0),
                payload: Box::new([]),
            };

            // this_msg belongs to current range, should be accepted
            assert!(matches!(buf.push(channel.clone(), this_msg), Ok(Some(_))));
            // this_msg belongs to next valid range that must be set as current by now
            assert!(matches!(buf.push(channel, next_msg), Ok(Some(_))));
        }

        #[test]
        fn returns_sorted_batch() {
            let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
            let mut buf = SendBuffer::from_batch_and_offset(10, 1);
            let mut record_ids = (10u32..20).collect::<Vec<_>>();
            record_ids.shuffle(&mut thread_rng());

            for record in record_ids {
                let msg = MessageEnvelope {
                    record_id: RecordId::from(record),
                    payload: Box::new([]),
                };

                if let Some(batch) = buf.push(channel.clone(), msg).ok().flatten() {
                    // todo: use https://doc.rust-lang.org/std/vec/struct.Vec.html#method.is_sorted_by
                    // or https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.is_sorted when stable
                    let is_sorted = batch
                        .as_slice()
                        .windows(2)
                        .all(|w| w[0].record_id.cmp(&w[1].record_id) != Ordering::Greater);

                    assert!(is_sorted, "batch {batch:?} is not sorted by record_id");
                }
            }
        }
    }
}
