use crate::{
    ff::Serializable,
    helpers::{Message, MESSAGE_PAYLOAD_SIZE_BYTES},
};
use generic_array::GenericArray;
use typenum::U8;

/// An adapter to send messages of the fixed size because [`OrderingMpscSender`] is generic over
/// message type.
#[derive(Debug)]
pub(super) struct Wrapper(pub [u8; Self::SIZE]);

impl Serializable for Wrapper {
    type Size = U8;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self((*buf).into())
    }
}

impl Message for Wrapper {}

impl Wrapper {
    const SIZE: usize = MESSAGE_PAYLOAD_SIZE_BYTES;

    pub fn wrap<M: Message>(v: M) -> Self {
        let mut buf = GenericArray::default();
        v.serialize(&mut buf);
        let mut this = [0_u8; Self::SIZE];
        this[..buf.len()].copy_from_slice(&buf);
        Self(this)
    }
}
