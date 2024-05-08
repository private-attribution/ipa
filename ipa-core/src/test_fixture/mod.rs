pub mod input;
mod sharing;
#[cfg(feature = "in-memory-infra")]
mod world;

// `test-fixture` module is enabled for all tests, but app makes sense only for tests that use
// in-memory infra.
#[cfg(feature = "in-memory-infra")]
mod app;

#[cfg(feature = "in-memory-infra")]
pub mod circuit;
mod event_gen;
pub mod ipa;
pub mod logging;
pub mod metrics;

use std::fmt::Debug;

#[cfg(feature = "in-memory-infra")]
pub use app::TestApp;
pub use event_gen::{Config as EventGeneratorConfig, EventGenerator};
use futures::TryFuture;
use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng};
use rand_core::{CryptoRng, RngCore};
pub use sharing::{get_bits, into_bits, Reconstruct, ReconstructArr};
#[cfg(feature = "in-memory-infra")]
pub use world::{
    Distribute, Random as RandomInputDistribution, RoundRobin as RoundRobinInputDistribution,
    Runner, TestExecutionStep, TestWorld, TestWorldConfig, WithShards,
};

use crate::{
    ff::{Field, U128Conversions},
    protocol::prss::Endpoint as PrssEndpoint,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SharedValue,
    },
};

/// Generate three participants.
/// p1 is left of p2, p2 is left of p3, p3 is left of p1...
#[must_use]
pub fn make_participants<R: RngCore + CryptoRng>(r: &mut R) -> [PrssEndpoint; 3] {
    let setup1 = PrssEndpoint::prepare(r);
    let setup2 = PrssEndpoint::prepare(r);
    let setup3 = PrssEndpoint::prepare(r);
    let (pk1_l, pk1_r) = setup1.public_keys();
    let (pk2_l, pk2_r) = setup2.public_keys();
    let (pk3_l, pk3_r) = setup3.public_keys();

    let p1 = setup1.setup(&pk3_r, &pk2_l);
    let p2 = setup2.setup(&pk1_r, &pk3_l);
    let p3 = setup3.setup(&pk2_r, &pk1_l);

    [p1, p2, p3]
}

pub type ReplicatedShares<T> = [Vec<Replicated<T>>; 3];

/// Generate vector shares from vector of inputs for three participant
///
/// # Panics
/// If the input cannot be converted into the given value type `V` without truncation.
#[must_use]
pub fn generate_shares<V: SharedValue + U128Conversions>(input: &[u128]) -> ReplicatedShares<V>
where
    Standard: Distribution<V>,
{
    let mut rand = StepRng::new(100, 1);

    let len = input.len();
    let mut shares0 = Vec::with_capacity(len);
    let mut shares1 = Vec::with_capacity(len);
    let mut shares2 = Vec::with_capacity(len);

    for i in input {
        let [s0, s1, s2] = V::try_from(*i).unwrap().share_with(&mut rand);
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
/// # Errors
/// If one of the futures returned an error.
pub async fn try_join3_array<T: TryFuture>([f0, f1, f2]: [T; 3]) -> Result<[T::Ok; 3], T::Error> {
    futures::future::try_join3(f0, f1, f2)
        .await
        .map(|(a, b, c)| [a, b, c])
}

/// Wrapper for joining three things into an array.
/// # Panics
/// If the tasks return `Err`.
pub async fn join3<T>(a: T, b: T, c: T) -> [T::Ok; 3]
where
    T: TryFuture,
    T::Output: Debug,
    T::Ok: Debug,
    T::Error: Debug,
{
    let (a, b, c) = futures::future::try_join3(a, b, c).await.unwrap();
    [a, b, c]
}

/// Wrapper for joining three things from an iterator into an array.
/// # Panics
/// If the tasks return `Err` or if `a` is the wrong length.
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
pub fn bits_to_value<F: Field + U128Conversions>(x: &[F]) -> u128 {
    #[allow(clippy::cast_possible_truncation)]
    let v = x
        .iter()
        .enumerate()
        .fold(0, |acc, (i, &b)| acc + (b.as_u128() << i));
    v
}

/// Take a slice of bits in `{0,1} ⊆ F_p`, and reconstruct the integer in `F_p`
///
/// # Panics
/// If the input cannot be converted into the given field `F` without truncation.
pub fn bits_to_field<F: Field + U128Conversions>(x: &[F]) -> F {
    F::try_from(bits_to_value(x)).unwrap()
}
