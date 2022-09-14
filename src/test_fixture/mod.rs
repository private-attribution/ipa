pub mod circuit;
mod sharing;
mod world;

use crate::helpers::mock::TestHelperGateway;
use crate::protocol::Step;
use crate::prss::{SpaceIndex};
use crate::securemul::ProtocolContext;

pub use sharing::{share, validate_and_reconstruct};
pub use world::{TestStep, TestWorld};
pub use world::make as make_world;

/// Creates protocol contexts for 3 helpers
///
/// # Panics
/// Panics if world has more or less than 3 gateways/participants
#[must_use]
pub fn make_context<S: Step + SpaceIndex>(
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
