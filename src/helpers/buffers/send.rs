use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use std::ops::Range;


use crate::helpers::buffers::fsv::FixedSizeByteVec;
use crate::protocol::RecordId;

type ByteBuf = FixedSizeByteVec<8>;

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
pub(in crate::helpers) struct SendBuffer {
    items_in_batch: usize,
    batch_count: usize,
    inner: HashMap<ChannelId, ByteBuf>
}

#[derive(thiserror::Error, Debug)]
pub(in crate::helpers) enum PushError {
    #[error("Record {record_id:?} is out of accepted range {accepted_range:?}")]
    OutOfRange {
        channel_id: ChannelId,
        record_id: RecordId,
        accepted_range: Range<RecordId>,
    },
    #[error("Record already exists")]
    Duplicate,
}

pub struct SendBufferBuilder {
    items_in_batch: u32,
    batch_count: u32,
}

impl Default for SendBufferBuilder {
    fn default() -> Self {
        Self {
            items_in_batch: 1,
            batch_count: 1,
        }
    }
}

impl SendBufferBuilder {
    pub fn batch_count(&mut self, batch_count: u32) -> &mut Self {
        self.batch_count = batch_count;
        self
    }

    pub fn items_in_batch(&mut self, items_in_batch: u32) -> &mut Self {
        self.items_in_batch = items_in_batch;
        self
    }

    pub(in crate::helpers) fn build(&mut self) -> SendBuffer {
        SendBuffer::new(self)
    }
}

impl SendBuffer {
    fn new(builder: &SendBufferBuilder) -> Self {
        Self {
            items_in_batch: builder.items_in_batch as usize,
            batch_count: builder.batch_count as usize,
            inner: HashMap::default(),
        }
    }

    pub fn push(
        &mut self,
        channel_id: ChannelId,
        msg: MessageEnvelope,
    ) -> Result<Option<Vec<MessageEnvelope>>, PushError> {
        let vec = match self.inner.entry(channel_id.clone()) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => entry
                .insert(FixedSizeByteVec::new(self.batch_count, self.items_in_batch))
        };

        let start = RecordId::from(u32::try_from(vec.elements_drained()).unwrap());
        let end = RecordId::from(u32::try_from(vec.elements_drained() + vec.capacity()).unwrap());

        if !(start..end).contains(&msg.record_id) {
            return Err(PushError::OutOfRange {
                channel_id,
                record_id: msg.record_id,
                accepted_range: (start..end)
            })
        }

        let index: u32 = u32::from(msg.record_id) - u32::from(start);

        if msg.payload.len() > ByteBuf::N1 {
            panic!("Message payload ({} bytes) exceeds maximum size allowed ({} bytes)", msg.payload.len(), vec.bytes_per_element());
        }

        let mut payload = [0; ByteBuf::N1];
        payload[..msg.payload.len()].copy_from_slice(msg.payload.as_ref());
        if let Some(_) = vec.insert(index as usize, payload) {
            return Err(PushError::Duplicate)
        }

        Ok(if vec.ready() {
            let start_record_id = vec.elements_drained();
            let mut buf = vec.drain().unwrap();

            let envs = buf.chunks_mut(8).enumerate().map(|(i, chunk)| {
                let record_id = RecordId::from((start_record_id + i) as u32);
                let payload = chunk.to_vec().into_boxed_slice();
                MessageEnvelope { record_id, payload }
            }).collect::<Vec<_>>();

            Some(envs)
        } else {
            None
        })
    }
}


#[cfg(test)]
mod tests {
    use crate::helpers::Identity;
    use crate::protocol::{RecordId, UniqueStepId};
    use rand::seq::SliceRandom;
    use rand::thread_rng;
    use std::cmp::Ordering;
    use crate::helpers::buffers::send::{PushError, SendBufferBuilder};
    
    use crate::helpers::fabric::{ChannelId, MessageEnvelope};

    impl Clone for MessageEnvelope {
        fn clone(&self) -> Self {
            MessageEnvelope {
                record_id: self.record_id,
                payload: self.payload.clone()
            }
        }
    }

    #[test]
    fn rejects_records_out_of_range() {
        let record_id = RecordId::from(11);
        let mut buf = SendBufferBuilder::default().build();
        let msg = empty_msg(record_id);

        assert!(matches!(
                buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
                Err(PushError::OutOfRange { .. }),
            ));
    }

    #[test]
    fn does_not_corrupt_messages() {
        let c1 = ChannelId::new(Identity::H1, UniqueStepId::default());
        let mut buf = SendBufferBuilder::default()
            .items_in_batch(10)
            .build();

        let batch = (0u8..10).filter_map(|i| {
            let msg = MessageEnvelope {
                record_id: RecordId::from(u32::from(i)),
                payload: i.to_le_bytes().to_vec().into_boxed_slice()
            };
            buf.push(c1.clone(), msg).ok().flatten()
        }).next().unwrap();

        for v in batch {
            let payload = u64::from_le_bytes(v.payload.as_ref().try_into().unwrap());
            assert!(payload < u64::from(u8::MAX));

            assert_eq!(
                u32::from(payload as u8),
                u32::from(v.record_id),
            );
        }
    }

    #[test]
    fn offset_is_per_channel() {
        let mut buf = SendBufferBuilder::default().build();
        let c1 = ChannelId::new(Identity::H1, UniqueStepId::default());
        let c2 = ChannelId::new(Identity::H2, UniqueStepId::default());

        let m1 = empty_msg(0);
        let m2 = empty_msg(1);

        buf.push(c1.clone(), m1).unwrap();
        buf.push(c1, m2.clone()).unwrap();

        assert!(matches!(
                buf.push(c2, m2),
                Err(PushError::OutOfRange { .. }),
            ));
    }

    #[test]
    fn rejects_duplicates() {
        let mut buf = SendBufferBuilder::default()
            .items_in_batch(10)
            .build();
        let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
        let record_id = RecordId::from(3);
        let m1 = empty_msg(record_id);
        let m2 = empty_msg(record_id);

        assert!(matches!(buf.push(channel.clone(), m1), Ok(None)));
        assert!(matches!(
                buf.push(channel, m2),
                Err(PushError::Duplicate)
            ));
    }

    #[test]
    fn accepts_records_within_the_valid_range() {
        let mut buf = SendBufferBuilder::default()
            .items_in_batch(10)
            .build();
        let msg = empty_msg(5);

        assert!(matches!(
                buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
                Ok(None)
            ));
    }

    #[test]
    fn accepts_records_from_next_range_after_flushing() {
        let mut buf = SendBufferBuilder::default().build();
        let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
        let next_msg = empty_msg(1);
        let this_msg = empty_msg(0);

        // this_msg belongs to current range, should be accepted
        assert!(matches!(buf.push(channel.clone(), this_msg), Ok(Some(_))));
        // this_msg belongs to next valid range that must be set as current by now
        assert!(matches!(buf.push(channel, next_msg), Ok(Some(_))));
    }

    #[test]
    fn returns_sorted_batch() {
        let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
        let mut buf = SendBufferBuilder::default()
            .items_in_batch(10)
            .build();

        let mut record_ids = (0..10).collect::<Vec<_>>();
        record_ids.shuffle(&mut thread_rng());

        let mut batch_processed = false;
        for record in record_ids {
            let msg = empty_msg(record);

            if let Some(batch) = buf.push(channel.clone(), msg).ok().flatten() {
                // todo: use https://doc.rust-lang.org/std/vec/struct.Vec.html#method.is_sorted_by
                // or https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.is_sorted when stable
                let is_sorted = batch
                    .as_slice()
                    .windows(2)
                    .all(|w| w[0].record_id.cmp(&w[1].record_id) != Ordering::Greater);

                assert!(is_sorted, "batch {batch:?} is not sorted by record_id");
                batch_processed = true;
            }
        }

        assert!(batch_processed)
    }

    fn empty_msg<I: TryInto<u32>>(record_id: I) -> MessageEnvelope where I::Error: std::fmt::Debug {
        MessageEnvelope {
            record_id: RecordId::from(record_id.try_into().unwrap()),
            payload: Box::new([])
        }
    }
}