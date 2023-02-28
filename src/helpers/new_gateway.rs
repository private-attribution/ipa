use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::fmt::{Debug, Formatter};
use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};
use futures_util::stream::FuturesUnordered;
use generic_array::{ArrayLength, GenericArray};
use tinyvec::array_vec;
use tokio::sync::mpsc::Sender;
use typenum::{U8, Unsigned};
use crate::bits::Serializable;
use crate::helpers::buffers::{ordering_mpsc, OrderingMpscReceiver, OrderingMpscSender, UnorderedReceiver};
use crate::helpers::{Error, MESSAGE_PAYLOAD_SIZE_BYTES, Role};
use crate::helpers::messaging::{Message, TotalRecords};
use crate::helpers::network::{ChannelId, MessageEnvelope};
use crate::protocol::{RecordId, Step};

#[derive(Debug)]
struct Wrapper([u8; Self::SIZE]);

impl Wrapper {
    const SIZE: usize = 8;
}

impl Serializable for Wrapper {
    type Size = U8;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self((*buf).into())
    }
}

impl Message for Wrapper {

}

struct Gateway {
    senders: Arc<Mutex<HashMap<ChannelId, OrderingMpscSender<Wrapper>>>>,
    tx: Sender<OrderingMpscReceiver<Wrapper>>,
    unordered_recv: HashMap<ChannelId, UnorderedReceiver<>>
    // receivers: FuturesUnordered<OrderingMpscReceiver<Wrapper>>
    // receivers: Arc<Mutex<Vec<OrderingMpscReceiver<Wrapper>>>>,
}

impl Gateway {
    /// Returns a channel that is ready to send messages. There is lock/unlock penalty associated with it,
    /// so this method is not expected to be called on the hot path.
    ///
    /// ## Panics
    /// Once upon a time, one little baby mutex got poisoned and everyone around it panicked
    pub async fn channel(&self, channel_id: &ChannelId) -> OrderingMpscSender<Wrapper> {
        let mut senders = self.senders.lock().unwrap();
        // sad to clone
        match senders.entry(channel_id.clone()) {
            Entry::Occupied(entry) => {
                entry.get().clone()
            }
            Entry::Vacant(entry) => {
                // TODO: configurable
                let (tx, rx) = ordering_mpsc(format!("{:?}", channel_id), NonZeroUsize::new(16).unwrap());
                let tx = entry.insert(tx).clone();
                drop(senders);

                self.tx.send(rx).await.unwrap();
                tx
            }
        }
    }
}

struct Mesh<'a> {
    step: &'a Step,
    total_records: TotalRecords,
    sender: OrderingMpscSender<Wrapper>
}

impl <'a> Mesh<'a> {
    pub async fn send<T: Message>(
        &self,
        dest: Role,
        record_id: RecordId,
        msg: T,
    ) -> Result<(), Error> {
        if T::Size::USIZE > Wrapper::SIZE {
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

        let mut payload = [0u8; Wrapper::SIZE];
        let mut data = GenericArray::default();
        msg.serialize(&mut data);
        payload.copy_from_slice(&data);

        self.sender.send(record_id.into(), Wrapper(payload)).await.unwrap();
        Ok(())
    }

    pub async fn receive<T: Message>(&self, source: Role, record_id: RecordId) -> Result<T, Error> {
    }
}
