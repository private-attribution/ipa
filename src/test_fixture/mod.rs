pub mod circuit;
pub mod fabric;
pub mod logging;
mod sharing;
mod world;

use crate::ff::{Field, Fp31};
use crate::helpers::Identity;
use crate::protocol::context::ProtocolContext;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::Step;
use crate::secret_sharing::Replicated;
use rand::rngs::mock::StepRng;
use rand::thread_rng;

pub use sharing::{share, validate_and_reconstruct, validate_list_of_shares};
pub use world::{make as make_world, TestWorld};

/// Creates protocol contexts for 3 helpers
///
/// # Panics
/// Panics if world has more or less than 3 gateways/participants
#[must_use]
pub fn make_contexts<F: Field>(test_world: &TestWorld) -> [ProtocolContext<'_, F>; 3] {
    test_world
        .gateways
        .iter()
        .zip(&test_world.participants)
        .zip(Identity::all_variants())
        .map(|((gateway, participant), role)| ProtocolContext::new(*role, participant, gateway))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Narrows a set of contexts all at once.
/// Use by assigning like so: `let [c0, c1, c2] = narrow_contexts(&contexts, "test")`
///
/// # Panics
/// Never, but then Rust doesn't know that; this is only needed because we don't have `each_ref()`.
#[must_use]
pub fn narrow_contexts<'a, F: Field>(
    contexts: &[ProtocolContext<'a, F>; 3],
    step: &impl Step,
) -> [ProtocolContext<'a, F>; 3] {
    // This really wants <[_; N]>::each_ref()
    contexts
        .iter()
        .map(|c| c.narrow(step))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}

/// Generate three participants.
/// p1 is left of p2, p2 is left of p3, p3 is left of p1...
#[must_use]
pub fn make_participants() -> (PrssEndpoint, PrssEndpoint, PrssEndpoint) {
    let mut r = thread_rng();
    let setup1 = PrssEndpoint::prepare(&mut r);
    let setup2 = PrssEndpoint::prepare(&mut r);
    let setup3 = PrssEndpoint::prepare(&mut r);
    let (pk1_l, pk1_r) = setup1.public_keys();
    let (pk2_l, pk2_r) = setup2.public_keys();
    let (pk3_l, pk3_r) = setup3.public_keys();

    let p1 = setup1.setup(&pk3_r, &pk2_l);
    let p2 = setup2.setup(&pk1_r, &pk3_l);
    let p3 = setup3.setup(&pk2_r, &pk1_l);

    (p1, p2, p3)
}

pub type ReplicatedShares<T> = (Vec<Replicated<T>>, Vec<Replicated<T>>, Vec<Replicated<T>>);

// Generate vector shares from vector of inputs for three participant
#[must_use]
pub fn generate_shares<T: Field>(input: Vec<u128>) -> ReplicatedShares<T> {
    let mut rand = StepRng::new(100, 1);

    let len = input.len();
    let mut shares0 = Vec::with_capacity(len);
    let mut shares1 = Vec::with_capacity(len);
    let mut shares2 = Vec::with_capacity(len);

    for iter in input {
        let share = share(T::from(iter), &mut rand);
        shares0.push(share[0]);
        shares1.push(share[1]);
        shares2.push(share[2]);
    }
    (shares0, shares1, shares2)
}
