use crate::bits::Serializable;
use crate::{
    helpers::{messaging::Message, MESSAGE_PAYLOAD_SIZE_BYTES},
    protocol::{RecordId, Substep},
};
use std::io::ErrorKind;
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

impl Serializable for PublicKeyChunk {
    const SIZE_IN_BYTES: usize = MESSAGE_PAYLOAD_SIZE_BYTES;

    fn serialize(self, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.len() >= self.0.len() {
            buf[..Self::SIZE_IN_BYTES].copy_from_slice(&self.0);
            Ok(())
        } else {
            Err(std::io::Error::new(
                ErrorKind::WriteZero,
                format!(
                    "expected buffer to be at least {} bytes, but was only {} bytes",
                    Self::SIZE_IN_BYTES,
                    buf.len()
                ),
            ))
        }
    }
    fn deserialize(buf: &[u8]) -> std::io::Result<Self> {
        if Self::SIZE_IN_BYTES <= buf.len() {
            let mut chunk = [0; Self::SIZE_IN_BYTES];
            chunk.copy_from_slice(&buf[..Self::SIZE_IN_BYTES]);
            Ok(PublicKeyChunk(chunk))
        } else {
            Err(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                format!(
                    "expected buffer of size {}, but it was of size {}",
                    Self::SIZE_IN_BYTES,
                    buf.len()
                ),
            ))
        }
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
    use rand::thread_rng;
    use x25519_dalek::EphemeralSecret;

    #[test]
    fn chunk_ser_de() {
        let chunk_bytes = [1, 2, 3, 4, 5, 6, 7, 8];
        let chunk = PublicKeyChunk(chunk_bytes);

        let mut serialized = [0u8; 8];
        chunk.serialize(&mut serialized).unwrap();
        assert_eq!(chunk_bytes, serialized);

        let deserialized = PublicKeyChunk::deserialize(&serialized).unwrap();
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
