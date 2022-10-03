pub mod circuit;
pub mod logging;
mod sharing;
mod world;
mod fabric;

use crate::helpers::mock::TestHelperGateway;
use crate::helpers::prss::{Participant, ParticipantSetup, SpaceIndex};
use crate::protocol::context::ProtocolContext;
use crate::protocol::Step;
use rand::thread_rng;

pub use sharing::{share, validate_and_reconstruct};
pub use world::make as make_world;
pub use world::{TestStep, TestWorld};

/// Creates protocol contexts for 3 helpers
///
/// # Panics
/// Panics if world has more or less than 3 gateways/participants
#[must_use]
pub fn make_contexts<S: Step + SpaceIndex>(
    test_world: &TestWorld<S>,
) -> [ProtocolContext<TestHelperGateway<S>, S>; 3] {
    test_world
        .gateways
        .iter()
        .zip(&test_world.participants)
        .map(|(gateway, participant)| ProtocolContext::new(participant, gateway))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Generate three participants.
/// p1 is left of p2, p2 is left of p3, p3 is left of p1...
#[must_use]
pub fn make_participants<I: SpaceIndex>() -> (Participant<I>, Participant<I>, Participant<I>) {
    let mut r = thread_rng();
    let setup1 = ParticipantSetup::new(&mut r);
    let setup2 = ParticipantSetup::new(&mut r);
    let setup3 = ParticipantSetup::new(&mut r);
    let (pk1_l, pk1_r) = setup1.public_keys();
    let (pk2_l, pk2_r) = setup2.public_keys();
    let (pk3_l, pk3_r) = setup3.public_keys();

    let p1 = setup1.setup(&pk3_r, &pk2_l);
    let p2 = setup2.setup(&pk1_r, &pk3_l);
    let p3 = setup3.setup(&pk2_r, &pk1_l);

    (p1, p2, p3)
}
