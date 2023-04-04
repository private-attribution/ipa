use crate::{
    helpers::{Direction, Error},
    protocol::{prss, RecordId, Step, Substep},
};
use futures_util::future::try_join4;

use rand_core::{CryptoRng, RngCore};



use x25519_dalek::PublicKey;

pub struct PrssExchangeStep;

impl AsRef<str> for PrssExchangeStep {
    fn as_ref(&self) -> &str {
        "prss_exchange"
    }
}

impl Substep for PrssExchangeStep {}

/// establish the prss endpoint by exchanging public keys with the other helpers
/// # Errors
/// if communication with other helpers fails
pub async fn negotiate<T: Transport, R: RngCore + CryptoRng>(
    gateway: &GatewayBase<T>,
    step: &Step,
    rng: &mut R,
) -> Result<prss::Endpoint, Error> {
    // setup protocol to exchange prss public keys
    let step = step.narrow(&PrssExchangeStep);
    let left_channel = ChannelId::new(gateway.role().peer(Direction::Left), step.clone());
    let right_channel = ChannelId::new(gateway.role().peer(Direction::Right), step.clone());

    let left_sender = gateway.get_sender::<PublicKey>(&left_channel, 1.into());
    let right_sender = gateway.get_sender::<PublicKey>(&right_channel, 1.into());
    let left_receiver = gateway.get_receiver::<PublicKey>(&left_channel);
    let right_receiver = gateway.get_receiver::<PublicKey>(&right_channel);

    // setup local prss endpoint
    let ep_setup = prss::Endpoint::prepare(rng);
    let (send_left_pk, send_right_pk) = ep_setup.public_keys();
    let record_id = RecordId::FIRST;

    let (_, _, recv_left_pk, recv_right_pk) = try_join4(
        left_sender.send(record_id, send_left_pk),
        right_sender.send(record_id, send_right_pk),
        left_receiver.receive(record_id),
        right_receiver.receive(record_id),
    )
    .await?;

    Ok(ep_setup.setup(&recv_left_pk, &recv_right_pk))
}

use crate::helpers::{ChannelId, GatewayBase, Transport};
