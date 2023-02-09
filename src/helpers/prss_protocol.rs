use crate::{
    bits::Serializable,
    helpers::{
        messaging::{Gateway, Message},
        Direction, Error, MESSAGE_PAYLOAD_SIZE_BYTES,
    },
    protocol::{prss, RecordId, Step, Substep},
};
use futures_util::future::try_join4;
use generic_array::GenericArray;
use rand_core::{CryptoRng, RngCore};
use std::iter::zip;

use tinyvec::ArrayVec;
use x25519_dalek::PublicKey;

pub struct PrssExchangeStep;

impl AsRef<str> for PrssExchangeStep {
    fn as_ref(&self) -> &str {
        "prss_exchange"
    }
}

impl Substep for PrssExchangeStep {}

pub const PUBLIC_KEY_CHUNK_COUNT: usize = 4;

/// establish the prss endpoint by exchanging public keys with the other helpers
/// # Errors
/// if communication with other helpers fails
pub async fn negotiate<R: RngCore + CryptoRng>(
    gateway: &Gateway,
    step: &Step,
    rng: &mut R,
) -> Result<prss::Endpoint, Error> {
    // setup protocol to exchange prss public keys
    let step = step.narrow(&PrssExchangeStep);
    let channel = gateway.mesh(&step, PUBLIC_KEY_CHUNK_COUNT.into());

    let left_peer = gateway.role().peer(Direction::Left);
    let right_peer = gateway.role().peer(Direction::Right);

    // setup local prss endpoint
    let ep_setup = prss::Endpoint::prepare(rng);
    let (send_left_pk, send_right_pk) = ep_setup.public_keys();
    let send_left_pk_chunks = PublicKeyChunk::chunks(send_left_pk);
    let send_right_pk_chunks = PublicKeyChunk::chunks(send_right_pk);

    // exchange public keys
    // TODO: since we have a limitation that max message size is 8 bytes, we must send 4
    //       messages to completely send the public key. If that max message size is removed, we
    //       can eliminate the chunking
    let mut recv_left_pk_builder = PublicKeyBytesBuilder::empty();
    let mut recv_right_pk_builder = PublicKeyBytesBuilder::empty();

    for (i, (send_left_chunk, send_right_chunk)) in
        zip(send_left_pk_chunks, send_right_pk_chunks).enumerate()
    {
        let record_id = RecordId::from(i);
        let send_to_left = channel.send(left_peer, record_id, send_left_chunk);
        let send_to_right = channel.send(right_peer, record_id, send_right_chunk);
        let recv_from_left = channel.receive::<PublicKeyChunk>(left_peer, record_id);
        let recv_from_right = channel.receive::<PublicKeyChunk>(right_peer, record_id);
        let (_, _, recv_left_key_chunk, recv_right_key_chunk) =
            try_join4(send_to_left, send_to_right, recv_from_left, recv_from_right).await?;
        recv_left_pk_builder.append_chunk(recv_left_key_chunk);
        recv_right_pk_builder.append_chunk(recv_right_key_chunk);
    }

    let recv_left_pk = recv_left_pk_builder
        .build()
        .map_err(|err| Error::serialization_error(err.record_id(), &step, err))?;
    let recv_right_pk = recv_right_pk_builder
        .build()
        .map_err(|err| Error::serialization_error(err.record_id(), &step, err))?;

    Ok(ep_setup.setup(&recv_left_pk, &recv_right_pk))
}

#[derive(thiserror::Error, Debug, PartialEq, Eq)]
#[error("missing {} chunks when trying to build public key", PublicKeyBytesBuilder::FULL_COUNT - incomplete_count)]
pub struct IncompletePublicKey {
    incomplete_count: u8,
}

impl IncompletePublicKey {
    #[must_use]
    pub fn record_id(&self) -> RecordId {
        RecordId::from(u32::from(self.incomplete_count))
    }
}

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

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        Self((*buf).into())
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
    use x25519_dalek::{EphemeralSecret, PublicKey};

    #[test]
    fn chunk_ser_de() {
        let chunk_bytes = GenericArray::from_slice(&[1u8, 2, 3, 4, 5, 6, 7, 8]);
        let chunk = PublicKeyChunk(chunk_bytes.as_slice().try_into().unwrap());

        let mut serialized = GenericArray::default();
        chunk.serialize(&mut serialized);
        assert_eq!(chunk_bytes, &serialized);

        let deserialized = PublicKeyChunk::deserialize(&serialized);
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
            let expected_err = Err(IncompletePublicKey {
                incomplete_count: u8::try_from(i).unwrap(),
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
