pub mod input;
mod sharing;
mod world;

pub mod circuit;
pub mod logging;
pub mod metrics;
pub mod net;
mod transport;

use crate::ff::{Field, Fp31};
use crate::protocol::context::Context;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::Substep;
use crate::rand::thread_rng;
use crate::secret_sharing::{
    replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SecretSharing,
};
use futures::future::try_join_all;
use futures::TryFuture;
use rand::distributions::Standard;
use rand::prelude::Distribution;
use rand::rngs::mock::StepRng;
pub use sharing::{get_bits, into_bits, Reconstruct};
use std::fmt::Debug;
pub use world::{Runner, TestWorld, TestWorldConfig};

/// Narrows a set of contexts all at once.
/// Use by assigning like so: `let [c0, c1, c2] = narrow_contexts(&contexts, "test")`
///
/// # Panics
/// Never, but then Rust doesn't know that; this is only needed because we don't have `each_ref()`.
#[must_use]
pub fn narrow_contexts<C: Debug + Context<F, Share = S>, F: Field, S: SecretSharing<F>>(
    contexts: &[C; 3],
    step: &impl Substep,
) -> [C; 3] {
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
        let [s0, s1, s2] = F::from(*i).share_with(&mut rand);
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

/// Take a slice of bits in `{0,1} ⊆ F_p`, and reconstruct the integer in `Z`
pub fn bits_to_value<F: Field>(x: &[F]) -> u128 {
    #[allow(clippy::cast_possible_truncation)]
    let v = x
        .iter()
        .enumerate()
        .fold(0, |acc, (i, &b)| acc + (b.as_u128() << i));
    v
}

/// Take a slice of bits in `{0,1} ⊆ F_p`, and reconstruct the integer in `F_p`
pub fn bits_to_field<F: Field>(x: &[F]) -> F {
    F::from(bits_to_value(x))
}
