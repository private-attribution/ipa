use std::iter::zip;
use rand_core::{CryptoRng, RngCore};
use crate::helpers::{Direction, Error};
use crate::helpers::messaging::Gateway;
use crate::helpers::old_http::prss_exchange_protocol::{PublicKeyBytesBuilder, PublicKeyChunk};
use crate::protocol::{prss, RecordId, Step, Substep};

struct PrssExchangeStep;

impl AsRef<str> for PrssExchangeStep {
    fn as_ref(&self) -> &str {
        "prss_exchange"
    }
}

impl Substep for PrssExchangeStep {}

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
    let channel = gateway.mesh(&step);

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

    for (i, (send_left_chunk, send_right_chunk)) in zip(send_left_pk_chunks, send_right_pk_chunks).enumerate()
    {
        let record_id = RecordId::from(i);
        let send_to_left = channel.send(left_peer, record_id, send_left_chunk);
        let send_to_right = channel.send(right_peer, record_id, send_right_chunk);
        let recv_from_left = channel.receive::<PublicKeyChunk>(left_peer, record_id);
        let recv_from_right = channel.receive::<PublicKeyChunk>(right_peer, record_id);
        let (_, _, recv_left_key_chunk, recv_right_key_chunk) =
            tokio::try_join!(send_to_left, send_to_right, recv_from_left, recv_from_right)?;
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
