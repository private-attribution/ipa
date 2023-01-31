use crate::bits::Serializable;
use crate::{
    helpers::{messaging::Message, MESSAGE_PAYLOAD_SIZE_BYTES},
    protocol::{RecordId, Substep},
};

use generic_array::GenericArray;

use tinyvec::ArrayVec;
use x25519_dalek::PublicKey;

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("missing {} chunks when trying to build public key", PublicKeyBytesBuilder::FULL_COUNT - incomplete_count)]
pub struct IncompletePublicKey {
    incomplete_count: u8,
}

impl IncompletePublicKey {
    pub fn record_id(&self) -> RecordId {
        RecordId::from(u32::from(self.incomplete_count))
    }
}

pub struct PrssExchangeStep;

impl AsRef<str> for PrssExchangeStep {
    fn as_ref(&self) -> &str {
        "prss_exchange"
    }
}

impl Substep for PrssExchangeStep {}

pub const PUBLIC_KEY_CHUNK_COUNT: usize = 4;

#[derive(Debug, Default, PartialEq, Eq, Copy, Clone)]
pub struct PublicKeyChunk([u8; 8]);

impl PublicKeyChunk {
    pub fn chunks(pk: PublicKey) -> [PublicKeyChunk; PUBLIC_KEY_CHUNK_COUNT] {
        let pk_bytes = pk.to_bytes();

        // These assumptions are necessary for ser/de to work
        assert_eq!(MESSAGE_PAYLOAD_SIZE_BYTES, 8);
        assert_eq!(pk_bytes.len(), 32);

        pk_bytes
            .chunks(MESSAGE_PAYLOAD_SIZE_BYTES)
            .map(|chunk| {
                let mut chunk_bytes = [0u8; MESSAGE_PAYLOAD_SIZE_BYTES];
                chunk_bytes.copy_from_slice(chunk);
                PublicKeyChunk(chunk_bytes)
            })
            .collect::<ArrayVec<[PublicKeyChunk; PUBLIC_KEY_CHUNK_COUNT]>>()
            .into_inner()
    }

    pub fn into_inner(self) -> [u8; MESSAGE_PAYLOAD_SIZE_BYTES] {
        self.0
    }
}

use crate::helpers::MessagePayloadArrayLen;

impl Serializable for PublicKeyChunk {
    type Size = MessagePayloadArrayLen;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        buf.copy_from_slice(&self.0);
    }

    fn deserialize(buf: GenericArray<u8, Self::Size>) -> Self {
        Self(buf.into())
    }
}

impl Message for PublicKeyChunk {}

#[derive(Debug, Default)]
pub struct PublicKeyBytesBuilder {
    bytes: ArrayVec<[u8; 32]>,
    count: u8,
}

impl PublicKeyBytesBuilder {
    #[allow(clippy::cast_possible_truncation)]
    const FULL_COUNT: u8 = PUBLIC_KEY_CHUNK_COUNT as u8;

    pub fn empty() -> Self {
        PublicKeyBytesBuilder {
            bytes: ArrayVec::new(),
            count: 0,
        }
    }
    pub fn append_chunk(&mut self, chunk: PublicKeyChunk) {
        self.bytes.extend_from_slice(&chunk.into_inner());
        self.count += 1;
    }
    pub fn build(self) -> Result<PublicKey, IncompletePublicKey> {
        if self.count == PublicKeyBytesBuilder::FULL_COUNT {
            Ok(self.bytes.into_inner().into())
        } else {
            Err(IncompletePublicKey {
                incomplete_count: self.count,
            })
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use generic_array::GenericArray;
    use rand::thread_rng;
    use x25519_dalek::EphemeralSecret;

    #[test]
    fn chunk_ser_de() {
        let chunk_bytes = GenericArray::from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8]);
        let chunk = PublicKeyChunk(chunk_bytes.as_slice().try_into().unwrap());

        let mut serialized = GenericArray::default();
        chunk.serialize(&mut serialized);
        assert_eq!(chunk_bytes, &serialized);

        let deserialized = PublicKeyChunk::deserialize(serialized);
        assert_eq!(chunk, deserialized);
    }

    #[test]
    fn incomplete_pk() {
        let secret = EphemeralSecret::new(thread_rng());
        let pk = PublicKey::from(&secret);

        let chunks = PublicKeyChunk::chunks(pk);

        // check incomplete keys fail
        for i in 0..chunks.len() {
            let mut builder = PublicKeyBytesBuilder::empty();
            for chunk in chunks.iter().take(i) {
                builder.append_chunk(*chunk);
            }
            let built = builder.build();
            #[allow(clippy::cast_possible_truncation)] // size is <= 4
            let expected_err = Err(IncompletePublicKey {
                incomplete_count: i as u8,
            });
            assert_eq!(built, expected_err);
        }

        // check complete key succeeds
        let mut builder = PublicKeyBytesBuilder::empty();
        for chunk in chunks {
            builder.append_chunk(chunk);
        }
        assert_eq!(builder.build(), Ok(pk));
    }
}
