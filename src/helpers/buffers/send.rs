use crate::helpers::{
    buffers::fsv::FixedSizeByteVec, network::ChannelId, network::MessageEnvelope,
    MESSAGE_PAYLOAD_SIZE_BYTES,
};
use std::{collections::HashMap, num::NonZeroUsize};

/// Use the buffer that allocates 8 bytes per element. It could probably go down to 4 if the
/// only thing IPA sends is a single field value. To support arbitrarily sized values, it needs
/// to be at least 16 bytes to be able to store a fat pointer in it.
type ByteBuf = FixedSizeByteVec<{ MESSAGE_PAYLOAD_SIZE_BYTES }>;

/// Buffer that keeps messages that must be sent to other helpers
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct SendBuffer {
    items_in_batch: NonZeroUsize,
    batch_count: NonZeroUsize,
    pub(super) inner: HashMap<ChannelId, ByteBuf>,
}

/// Send buffer configuration is defined over two parameters. `items_in_batch` indicates how many
/// elements a single request to send data to network layer can hold. The size of the batch in
/// bytes is defined as `items_in_batch` * `ByteBuf::ELEMENT_SIZE_BYTES`.
///
/// `batch_count` defines the overall capacity of the send buffer as `items_in_batch` * `batch_count`.
/// Setting it to `2` will double the capacity of the send buffer as at most two batches can be kept
/// in memory, `4` quadruples the capacity etc.
#[derive(Debug, Copy, Clone)]
pub struct Config {
    pub items_in_batch: NonZeroUsize,
    pub batch_count: NonZeroUsize,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            items_in_batch: NonZeroUsize::new(1).unwrap(),
            batch_count: NonZeroUsize::new(16).unwrap(),
        }
    }
}

impl SendBuffer {
    pub fn new(config: Config) -> Self {
        Self {
            items_in_batch: config.items_in_batch,
            batch_count: config.batch_count,
            inner: HashMap::default(),
        }
    }

    pub fn push(&mut self, channel_id: &ChannelId, msg: &MessageEnvelope) -> Option<Vec<u8>> {
        debug_assert!(
            msg.payload.len() <= ByteBuf::ELEMENT_SIZE_BYTES,
            "Message payload exceeds the maximum allowed size"
        );

        let buf = if let Some(buf) = self.inner.get_mut(channel_id) {
            buf
        } else {
            self.inner.entry(channel_id.clone()).or_insert_with(|| {
                let size =
                    NonZeroUsize::new(self.batch_count.get() * self.items_in_batch.get()).unwrap();
                FixedSizeByteVec::new(size)
            })
        };

        // TODO: avoid the copy here and size the element size to the message type.
        let mut payload = [0; ByteBuf::ELEMENT_SIZE_BYTES];
        payload[..msg.payload.len()].copy_from_slice(&msg.payload);
        buf.insert(channel_id, usize::from(msg.record_id), &payload);
        buf.take(self.items_in_batch.get())
    }

    #[cfg(debug_assertions)]
    pub(in crate::helpers) fn waiting(&self) -> super::waiting::WaitingTasks {
        use super::waiting::WaitingTasks;

        let mut tasks = HashMap::new();
        for (channel, buf) in &self.inner {
            let missing = buf.missing();
            if !missing.is_empty() {
                tasks.insert(
                    channel,
                    missing
                        .map(|v| u32::try_from(v).unwrap())
                        .collect::<Vec<_>>(),
                );
            }
        }

        WaitingTasks::new(tasks)
    }
}

impl Config {
    #[must_use]
    pub fn batch_count(self, batch_count: NonZeroUsize) -> Self {
        Self {
            items_in_batch: self.items_in_batch,
            batch_count,
        }
    }

    #[must_use]
    pub fn items_in_batch(self, items_in_batch: NonZeroUsize) -> Self {
        Self {
            items_in_batch,
            batch_count: self.batch_count,
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        helpers::Role,
        protocol::{RecordId, Step},
    };
    use tinyvec::array_vec;

    impl Clone for MessageEnvelope {
        fn clone(&self) -> Self {
            MessageEnvelope {
                record_id: self.record_id,
                // tinyvec implements copy for small arrays
                payload: self.payload,
            }
        }
    }

    #[test]
    #[should_panic]
    fn rejects_records_out_of_range() {
        let record_id = RecordId::from(11_u32);
        let mut buf = SendBuffer::new(Config {
            items_in_batch: NonZeroUsize::new(1).unwrap(),
            batch_count: NonZeroUsize::new(1).unwrap(),
        });
        let msg = empty_msg(record_id);

        assert_eq!(
            buf.push(&ChannelId::new(Role::H1, Step::default()), &msg),
            None
        );
    }

    #[test]
    fn does_not_corrupt_messages() {
        let c1 = ChannelId::new(Role::H1, Step::default());
        let config = Config::default().items_in_batch(NonZeroUsize::new(10).unwrap());
        let mut buf = SendBuffer::new(config);

        let batch = (0u8..10)
            .find_map(|i| {
                let msg = MessageEnvelope {
                    record_id: RecordId::from(u32::from(i)),
                    payload: array_vec!([u8; ByteBuf::ELEMENT_SIZE_BYTES] => i),
                };
                buf.push(&c1, &msg)
            })
            .unwrap();

        for (i, v) in batch.chunks(ByteBuf::ELEMENT_SIZE_BYTES).enumerate() {
            let payload = u64::from_le_bytes(v.try_into().unwrap());
            assert!(payload < u64::from(u8::MAX));

            assert_eq!(usize::from(u8::try_from(payload).unwrap()), i);
        }
    }

    #[test]
    #[cfg(debug_assertions)] // assertions only generated for debug builds
    #[should_panic(expected = "Attempt to insert out of range at index 1 (allowed=0..1)")]
    fn offset_is_per_channel() {
        let mut buf = SendBuffer::new(Config {
            items_in_batch: NonZeroUsize::new(1).unwrap(),
            batch_count: NonZeroUsize::new(1).unwrap(),
        });
        let c1 = ChannelId::new(Role::H1, Step::default());
        let c2 = ChannelId::new(Role::H2, Step::default());

        let m1 = empty_msg(0);
        let m2 = empty_msg(1);

        buf.push(&c1, &m1).unwrap();
        buf.push(&c1, &m2).unwrap();

        assert!(buf.push(&c2, &m2).is_none());
    }

    #[test]
    #[cfg(debug_assertions)] // assertions only generated for debug builds
    #[should_panic(expected = "Duplicate send for index 3")]
    fn rejects_duplicates() {
        let config = Config::default().items_in_batch(NonZeroUsize::new(10).unwrap());
        let mut buf = SendBuffer::new(config);
        let channel = ChannelId::new(Role::H1, Step::default());
        let record_id = RecordId::from(3_u32);
        let m1 = empty_msg(record_id);
        let m2 = empty_msg(record_id);

        assert!(buf.push(&channel, &m1).is_none());
        assert!(buf.push(&channel, &m2).is_none()); // This throws.
    }

    #[test]
    fn accepts_records_within_the_valid_range() {
        let config = Config::default().items_in_batch(NonZeroUsize::new(10).unwrap());
        let mut buf = SendBuffer::new(config);
        let msg = empty_msg(5);

        assert!(buf
            .push(&ChannelId::new(Role::H1, Step::default()), &msg)
            .is_none());
    }

    #[test]
    fn accepts_records_from_next_range_after_flushing() {
        let mut buf = SendBuffer::new(Config::default());
        let channel = ChannelId::new(Role::H1, Step::default());
        let next_msg = empty_msg(1);
        let this_msg = empty_msg(0);

        // this_msg belongs to current range, should be accepted
        assert!(buf.push(&channel, &this_msg).is_some());
        // this_msg belongs to next valid range that must be set as current by now
        assert!(buf.push(&channel, &next_msg).is_some());
    }

    fn empty_msg<I: TryInto<u32>>(record_id: I) -> MessageEnvelope
    where
        I::Error: std::fmt::Debug,
    {
        MessageEnvelope {
            record_id: RecordId::from(record_id.try_into().unwrap()),
            payload: array_vec!(),
        }
    }
}
