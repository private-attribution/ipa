use crate::helpers::fabric::{ChannelId, MessageEnvelope};
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::mem;
use crate::helpers::buffers::fsv;
use crate::helpers::buffers::fsv::FixedSizeByteVec;
use crate::protocol::RecordId;

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
pub(in crate::helpers) struct SendBuffer {
    max_capacity: usize,
    inner: HashMap<ChannelId, fsv::FixedSizeByteVec<8>>
}

impl SendBuffer {
    pub fn new(max_channel_capacity: u32) -> Self {
        Self {
            max_capacity: max_channel_capacity as usize,
            inner: HashMap::default(),
        }
    }

    pub fn push(
        &mut self,
        channel_id: ChannelId,
        msg: MessageEnvelope,
    ) -> Option<Vec<MessageEnvelope>> {
        let (index, vec) = match self.inner.entry(channel_id) {
            Entry::Occupied(entry) => {
                let vec = entry.into_mut();

                (u32::from(msg.record_id) as usize, vec)
            }
            Entry::Vacant(entry) => {
                let vec = entry.insert(FixedSizeByteVec::new(4, self.max_capacity));

                // todo return error if record is out of range
                (u32::from(msg.record_id) as usize - vec.elements_drained(), vec)
            }
        };

        vec.insert(index, msg.payload.as_ref().try_into().unwrap());

        if vec.ready() {
            let start_record_id = vec.elements_drained();
            let mut buf = vec.drain().unwrap();

            let envs = buf.chunks_mut(8).enumerate().map(|(i, chunk)| {
                let record_id = RecordId::from((start_record_id + i) as u32);
                let payload = chunk.to_vec().into_boxed_slice();
                MessageEnvelope { record_id, payload }
            }).collect::<Vec<_>>();

            Some(envs)
            // Some(vec.drain())
        } else {
            None
        }

        // if vec.len() >= self.max_capacity {
        //     let data = mem::replace(vec, Vec::with_capacity(self.max_capacity));
        //     Some(data)
        // } else {
        //     None
        // }
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn remove_random(&mut self) -> (ChannelId, Vec<MessageEnvelope>) {
        panic!("no longer support remove random")
        // assert!(self.len() > 0);
        //
        // let channel_id = self.inner.keys().next().unwrap().clone();
        // let data = self.inner.remove(&channel_id).unwrap();
        //
        // (channel_id, data)
    }

}


// #[cfg(test)]
// mod tests {
//     use crate::helpers::buffers::{SendBuffer, SendBufferConfig, SendBufferError};
//     use crate::helpers::fabric::{ByteBuf, ChannelId, InlineBuf, MessageEnvelope};
//     use crate::helpers::Identity;
//     use crate::protocol::{RecordId, UniqueStepId};
//     use rand::seq::SliceRandom;
//     use rand::thread_rng;
//     use std::cmp::Ordering;
//
//     impl From<u32> for SendBufferConfig {
//         fn from(flush_threshold: u32) -> Self {
//             Self {
//                 total_capacity: flush_threshold,
//                 flush_threshold
//             }
//         }
//     }
//
//     #[test]
//     fn rejects_records_out_of_range() {
//         let record_id = RecordId::from(11);
//         let accepted_range = RecordId::from(0)..RecordId::from(10);
//         let mut buf = SendBuffer::new(10);
//         let msg = MessageEnvelope {
//             record_id,
//             payload: ByteBuf::default(),
//         };
//
//         assert!(matches!(
//                 buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
//                 Err(SendBufferError::RecordOutOfRange { record_id, accepted_range: range }) if record_id == record_id && range == accepted_range
//             ));
//     }
//
//     #[test]
//     fn offset_is_per_channel() {
//         let mut buf = SendBuffer::new(1);
//         let c1 = ChannelId::new(Identity::H1, UniqueStepId::default());
//         let c2 = ChannelId::new(Identity::H2, UniqueStepId::default());
//
//         let m1 = MessageEnvelope {
//             record_id: RecordId::from(0),
//             payload: ByteBuf::default(),
//         };
//         let m2 = MessageEnvelope {
//             record_id: RecordId::from(1),
//             payload: ByteBuf::default(),
//         };
//
//         buf.push(c1.clone(), m1).unwrap();
//         buf.push(c1, m2.clone()).unwrap();
//
//         assert!(matches!(
//                 buf.push(c2, m2),
//                 Err(SendBufferError::RecordOutOfRange { .. })
//             ));
//     }
//
//     #[test]
//     fn rejects_duplicates() {
//         let mut buf = SendBuffer::new(10);
//         let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
//         let record_id = RecordId::from(3);
//         let m1 = MessageEnvelope {
//             record_id,
//             payload: ByteBuf::default(),
//         };
//         let m2 = MessageEnvelope {
//             record_id,
//             payload: ByteBuf::default(),
//         };
//
//         assert!(matches!(buf.push(channel.clone(), m1), Ok(None)));
//         assert!(matches!(
//                 buf.push(channel, m2),
//                 Err(SendBufferError::DuplicateMessage { record_id: _ })
//             ));
//     }
//
//     #[test]
//     fn accepts_records_within_the_valid_range() {
//         let mut buf = SendBuffer::new(10);
//         let msg = MessageEnvelope {
//             record_id: RecordId::from(5),
//             payload: ByteBuf::default(),
//         };
//
//         assert!(matches!(
//                 buf.push(ChannelId::new(Identity::H1, UniqueStepId::default()), msg),
//                 Ok(None)
//             ));
//     }
//
//     #[test]
//     fn accepts_records_from_next_range_after_flushing() {
//         let mut buf = SendBuffer::new(1);
//         let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
//         let next_msg = MessageEnvelope {
//             record_id: RecordId::from(1),
//             payload: ByteBuf::default(),
//         };
//         let this_msg = MessageEnvelope {
//             record_id: RecordId::from(0),
//             payload: ByteBuf::default(),
//         };
//
//         // this_msg belongs to current range, should be accepted
//         assert!(matches!(buf.push(channel.clone(), this_msg), Ok(Some(_))));
//         // this_msg belongs to next valid range that must be set as current by now
//         assert!(matches!(buf.push(channel, next_msg), Ok(Some(_))));
//     }
//
//     #[test]
//     fn returns_sorted_batch() {
//         let channel = ChannelId::new(Identity::H1, UniqueStepId::default());
//         let mut buf = SendBuffer::with_offset(10, 1);
//         let mut record_ids = (10u32..20).collect::<Vec<_>>();
//         record_ids.shuffle(&mut thread_rng());
//
//         for record in record_ids {
//             let msg = MessageEnvelope {
//                 record_id: RecordId::from(record),
//                 payload: ByteBuf::default(),
//             };
//
//             if let Some(batch) = buf.push(channel.clone(), msg).ok().flatten() {
//                 // todo: use https://doc.rust-lang.org/std/vec/struct.Vec.html#method.is_sorted_by
//                 // or https://doc.rust-lang.org/std/iter/trait.Iterator.html#method.is_sorted when stable
//                 let is_sorted = batch
//                     .as_slice()
//                     .windows(2)
//                     .all(|w| w[0].record_id.cmp(&w[1].record_id) != Ordering::Greater);
//
//                 assert!(is_sorted, "batch {batch:?} is not sorted by record_id");
//             }
//         }
//     }
// }