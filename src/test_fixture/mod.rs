mod sharing;
mod world;

pub mod circuit;
pub mod logging;
pub mod network;

use crate::ff::{Field, Fp31};
use crate::helpers::Role;
use crate::protocol::context::ProtocolContext;
use crate::protocol::malicious::SecurityValidator;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::Substep;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::rngs::mock::StepRng;
use rand::thread_rng;

pub use sharing::{
    share, share_malicious, validate_and_reconstruct, validate_list_of_shares,
    validate_list_of_shares_malicious,
};
pub use world::{
    make as make_world, make_with_config as make_world_with_config, TestWorld, TestWorldConfig,
};

/// Creates protocol contexts for 3 helpers
///
/// # Panics
/// Panics if world has more or less than 3 gateways/participants
#[must_use]
pub fn make_contexts<F: Field>(
    test_world: &TestWorld,
) -> [ProtocolContext<'_, Replicated<F>, F>; 3] {
    test_world
        .gateways
        .iter()
        .zip(&test_world.participants)
        .zip(Role::all())
        .map(|((gateway, participant), role)| ProtocolContext::new(*role, participant, gateway))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap()
}
pub struct MaliciousContext<'a, F: Field> {
    pub ctx: ProtocolContext<'a, MaliciousReplicated<F>, F>,
    pub validator: SecurityValidator<F>,
}

/// Creates malicious protocol contexts for 3 helpers.
pub fn make_malicious_contexts<F: Field>(test_world: &TestWorld) -> [MaliciousContext<'_, F>; 3] {
    make_contexts(test_world).map(|ctx| {
        let v = SecurityValidator::new(ctx.narrow("MaliciousValidate"));
        let acc = v.accumulator();

        MaliciousContext {
            ctx: ctx.upgrade_to_malicious(acc, v.r_share().clone()),
            validator: v,
        }
    })
}

/// Narrows a set of contexts all at once.
/// Use by assigning like so: `let [c0, c1, c2] = narrow_contexts(&contexts, "test")`
///
/// # Panics
/// Never, but then Rust doesn't know that; this is only needed because we don't have `each_ref()`.
#[must_use]
pub fn narrow_contexts<'a, F: Field, S: SecretSharing<F>>(
    contexts: &[ProtocolContext<'a, S, F>; 3],
    step: &impl Substep,
) -> [ProtocolContext<'a, S, F>; 3] {
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
pub fn make_participants() -> [PrssEndpoint; 3] {
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

    [p1, p2, p3]
}

pub type ReplicatedShares<T> = [Vec<Replicated<T>>; 3];
pub type MaliciousShares<T> = [Vec<MaliciousReplicated<T>>; 3];

// Generate vector shares from vector of inputs for three participant
#[must_use]
pub fn generate_shares<F: Field>(input: &[u128]) -> ReplicatedShares<F>
where
    Standard: Distribution<F>,
{
    let mut rand = StepRng::new(100, 1);

    let len = input.len();
    let mut shares0 = Vec::with_capacity(len);
    let mut shares1 = Vec::with_capacity(len);
    let mut shares2 = Vec::with_capacity(len);

    for i in input {
        let [s0, s1, s2] = share(F::from(*i), &mut rand);
        shares0.push(s0);
        shares1.push(s1);
        shares2.push(s2);
    }
    [shares0, shares1, shares2]
}

/// # Panics
/// Panics if the permutation is not a valid one.
/// Here "valid" means it contains all the numbers in the range 0..length, and each only appears once.
#[must_use]
pub fn permutation_valid(permutation: &[u32]) -> bool {
    let mut c = permutation.to_vec();
    c.sort_unstable();
    for (i, position) in c.iter().enumerate() {
        assert_eq!(*position as usize, i);
    }
    true
}
