mod sharing;
mod world;

pub mod circuit;
pub mod logging;
pub mod network;

use std::fmt::Debug;
use crate::error::Error;
use crate::ff::{Field, Fp31};
use crate::helpers::Role;
use crate::protocol::{
    context::ProtocolContext, malicious::SecurityValidator, prss::Endpoint as PrssEndpoint,
    RecordId, Substep,
};
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use futures::future::try_join_all;
use futures::TryFuture;
use rand::{
    distributions::{Distribution, Standard},
    rngs::mock::StepRng,
    thread_rng, RngCore,
};
use std::iter::{repeat, zip};

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

///
/// # Panics
/// If there are any errors upgrading the inputs to `MaliciousReplicated` it will panic
/// This can happen if there are any problems with the multiplications used to do so.
pub async fn make_malicious_contexts<'a, F: Field, R: RngCore>(
    test_world: &'a TestWorld,
    inputs: &[F],
    rng: &mut R,
) -> (
    [ProtocolContext<'a, MaliciousReplicated<F>, F>; 3],
    [SecurityValidator<F>; 3],
    [Vec<MaliciousReplicated<F>>; 3],
)
where
    Standard: Distribution<F>,
{
    let contexts = make_contexts(test_world);
    let validators: Vec<_> = contexts
        .iter()
        .map(|ctx| SecurityValidator::new(ctx.narrow("MaliciousValidate")))
        .collect();

    let mut helper0_shares = Vec::with_capacity(inputs.len());
    let mut helper1_shares = Vec::with_capacity(inputs.len());
    let mut helper2_shares = Vec::with_capacity(inputs.len());
    for input in inputs {
        let [sh0, sh1, sh2] = share(*input, rng);
        helper0_shares.push(sh0);
        helper1_shares.push(sh1);
        helper2_shares.push(sh2);
    }

    let malicious_stuff = try_join_all(
        zip(
            zip(contexts.into_iter(), validators.iter()),
            [helper0_shares, helper1_shares, helper2_shares],
        )
        .map(|((ctx, v), shares)| async move {
            try_join_all(
                zip(
                    repeat(v.r_share()),
                    zip(repeat(v.accumulator().clone()), zip(shares, repeat(ctx))),
                )
                .enumerate()
                .map(|(i, (r_share, (acc, (s, ctx))))| async move {
                    let record_id = RecordId::from(i);
                    ctx.narrow("upgrade_inputs")
                        .upgrade_to_malicious(acc, r_share.clone(), record_id, s)
                        .await
                }),
            )
            .await
        }),
    )
    .await
    .unwrap();

    let malicious_inputs = [
        malicious_stuff[0].iter().map(|(_, x)| x.clone()).collect(),
        malicious_stuff[1].iter().map(|(_, x)| x.clone()).collect(),
        malicious_stuff[2].iter().map(|(_, x)| x.clone()).collect(),
    ];

    let malicious_contexts = [
        malicious_stuff[0][0].0.clone(),
        malicious_stuff[1][0].0.clone(),
        malicious_stuff[2][0].0.clone(),
    ];

    (
        malicious_contexts,
        validators.try_into().unwrap(),
        malicious_inputs,
    )
}

/// # Errors
/// If any of the calls to validate fail, this will throw an error
pub async fn validate_circuit<F: Field>(
    contexts: [ProtocolContext<'_, MaliciousReplicated<F>, F>; 3],
    validators: [SecurityValidator<F>; 3],
) -> Result<(), Error> {
    let _validation_results = try_join_all(
        zip(validators, contexts.iter())
            .map(|(v, ctx)| async move { v.validate(ctx.narrow("validate_circuit")).await }),
    )
    .await?;
    Ok(())
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

/// Wrapper for joining three things into an array.
/// # Panics
/// Probably never, but the compiler doesn't know that.
pub async fn join3<T>(a: T, b: T, c: T) -> [T::Ok; 3]
where
    T: TryFuture,
    T::Output: Debug,
    T::Ok: Debug,
    T::Error: Debug,
{
    let x = try_join_all([a, b, c]).await.unwrap();
    <[_; 3]>::try_from(x).unwrap()
}

/// Wrapper for joining three things into an array.
/// # Panics
/// If `a` is the wrong length.
pub async fn join3v<T, V>(a: V) -> [T::Ok; 3]
where
    V: IntoIterator<Item = T>,
    T: TryFuture,
    T::Output: Debug,
    T::Ok: Debug,
    T::Error: Debug,
{
    let mut it = a.into_iter();
    let res = join3(it.next().unwrap(), it.next().unwrap(), it.next().unwrap()).await;
    assert!(it.next().is_none());
    res
}
