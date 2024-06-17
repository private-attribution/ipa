use futures_util::future::try_join4;
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::PublicKey;

use crate::{
    helpers::{ChannelId, Direction, Error, Gateway, Role, TotalRecords},
    protocol::{prss, Gate, RecordId},
};

/// Establish the prss endpoint by exchanging public keys with the other helpers.
/// # Errors
/// if communication with other helpers fails
pub async fn negotiate<R: RngCore + CryptoRng>(
    gateway: &Gateway,
    gate: &Gate,
    rng: &mut R,
) -> Result<prss::Endpoint, Error<Role>> {
    // setup protocol to exchange PRSS public keys. This protocol sends one message per peer.
    // Each message contains this helper's public key. At the end of this protocol, all helpers
    // have completed key exchange and each of them have established a shared secret with each peer.
    let left_channel = ChannelId::new(gateway.role().peer(Direction::Left), gate.clone());
    let right_channel = ChannelId::new(gateway.role().peer(Direction::Right), gate.clone());
    let total_records = TotalRecords::specified(1);

    let left_sender = gateway.get_mpc_sender::<PublicKey>(&left_channel, total_records);
    let right_sender = gateway.get_mpc_sender::<PublicKey>(&right_channel, total_records);
    let left_receiver = gateway.get_mpc_receiver::<PublicKey>(&left_channel);
    let right_receiver = gateway.get_mpc_receiver::<PublicKey>(&right_channel);

    // setup local prss endpoint
    let ep_setup = prss::Endpoint::prepare(rng);
    let (send_left_pk, send_right_pk) = ep_setup.public_keys();
    let record_id = RecordId::FIRST;

    let ((), (), recv_left_pk, recv_right_pk) = try_join4(
        left_sender.send(record_id, send_left_pk),
        right_sender.send(record_id, send_right_pk),
        left_receiver.receive(record_id),
        right_receiver.receive(record_id),
    )
    .await?;

    Ok(ep_setup.setup(&recv_left_pk, &recv_right_pk))
}
