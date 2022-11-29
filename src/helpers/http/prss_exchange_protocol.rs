use crate::{
    helpers::{messaging::Message, MESSAGE_PAYLOAD_SIZE_BYTES},
    protocol::Substep,
};
use std::io::ErrorKind;
use x25519_dalek::PublicKey;

pub struct PrssExchangeStep;

impl AsRef<str> for PrssExchangeStep {
    fn as_ref(&self) -> &str {
        "prss_exchange"
    }
}

impl Substep for PrssExchangeStep {}

#[derive(Debug)]
pub struct PublicKeyChunk([u8; MESSAGE_PAYLOAD_SIZE_BYTES]);

impl PublicKeyChunk {
    pub fn chunks(pk: PublicKey) -> [PublicKeyChunk; 4] {
        let pk_bytes = pk.to_bytes();

        // These assumptions are necessary for ser/de to work
        assert_eq!(MESSAGE_PAYLOAD_SIZE_BYTES, 8);
        assert_eq!(pk_bytes.len(), 32);

        let mut chunks = Vec::with_capacity(4);
        for i in 0..4 {
            let lower = i * MESSAGE_PAYLOAD_SIZE_BYTES;
            let upper = lower + MESSAGE_PAYLOAD_SIZE_BYTES;
            let mut chunk_bytes = [0; MESSAGE_PAYLOAD_SIZE_BYTES];
            chunk_bytes.copy_from_slice(&pk_bytes[lower..upper]);
            chunks.push(PublicKeyChunk(chunk_bytes));
        }
        chunks.try_into().unwrap()
    }

    pub fn into_inner(self) -> [u8; MESSAGE_PAYLOAD_SIZE_BYTES] {
        self.0
    }
}

impl Message for PublicKeyChunk {
    #[allow(clippy::cast_possible_truncation)]
    const SIZE_IN_BYTES: u32 = MESSAGE_PAYLOAD_SIZE_BYTES as u32;

    fn deserialize(buf: &mut [u8]) -> std::io::Result<Self> {
        if Self::SIZE_IN_BYTES as usize == buf.len() {
            let mut chunk = [0; Self::SIZE_IN_BYTES as usize];
            chunk.copy_from_slice(&buf[..Self::SIZE_IN_BYTES as usize]);
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

    fn serialize(self, buf: &mut [u8]) -> std::io::Result<()> {
        if buf.len() >= self.0.len() {
            buf[..Self::SIZE_IN_BYTES as usize].copy_from_slice(&self.0);
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
}
