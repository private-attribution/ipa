pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod reshare;
mod reveal;
mod share_known_value;
pub mod share_validation;
pub mod step;

use std::ops::Not;

pub use check_zero::semi_honest_check_zero;
pub use if_else::select;
pub use mul::{BooleanArrayMul, SecureMul};
pub use reshare::Reshare;
pub use reveal::{
    partial_reveal, reveal, semi_honest_reveal, Reveal, ThisCodeIsAuthorizedToObserveRevealedValues,
};
pub use share_known_value::ShareKnownValue;

use crate::{
    const_assert_eq,
    ff::{boolean::Boolean, ec_prime_field::Fp25519, PrimeField},
    protocol::{
        context::{Context, UpgradedMaliciousContext, UpgradedSemiHonestContext},
        ipa_prf::{AGG_CHUNK, PRF_CHUNK},
        prss::FromPrss,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare,
        },
        FieldSimd, SecretSharing, SharedValue, Vectorizable,
    },
    sharding::ShardBinding,
};

/// Basic suite of MPC protocols.
///
/// This is currently applicable only in unvectorized contexts, because `Reshare` and
/// `ShareKnownValue` are not vectorized. For this reason there is no `N` const parameter. The
/// alternate `VectorProtocols` can be used in vectorized contexts. With parity of supported
/// protocols, this could be merged with `VectorProtocols`.
pub trait BasicProtocols<C: Context, V: SharedValue + Vectorizable<1>>:
    SecretSharing<V>
    + Reshare<C>
    + Reveal<C, 1, Output = <V as Vectorizable<1>>::Array>
    + SecureMul<C>
    + ShareKnownValue<C, V>
{
}

impl<'a, B: ShardBinding, F: ExtendableField> BasicProtocols<UpgradedSemiHonestContext<'a, B, F>, F>
    for AdditiveShare<F>
{
}

impl<'a, F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousReplicated<F>
{
}

/// Basic suite of MPC protocols for vectorized data.
///
/// Like `BasicProtocols`, but without `Reshare` and `ShareKnownValue`, which are not vectorized.
/// (`ShareKnownValue` has the difficulty of resolving `V` vs. `[V; 1]` issues for the known value
/// type. `Reshare` hasn't been attempted.)
///
/// `VectorProtocols` also adds `FromPrss`, which would probably be reasonable to have in
/// `BasicProtocols` and `BooleanProtocols` as well.
pub trait VectorProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V> + Reveal<C, N, Output = <V as Vectorizable<N>>::Array> + SecureMul<C> + FromPrss
{
}

// For PRF test
impl<'a, B: ShardBinding> VectorProtocols<UpgradedSemiHonestContext<'a, B, Fp25519>, Fp25519>
    for AdditiveShare<Fp25519>
{
}

impl<'a, B: ShardBinding>
    VectorProtocols<UpgradedSemiHonestContext<'a, B, Fp25519>, Fp25519, PRF_CHUNK>
    for AdditiveShare<Fp25519, PRF_CHUNK>
{
}

/// Basic suite of MPC protocols for (possibly vectorized) boolean shares.
///
/// Adds the requirement that the type implements `Not`. Like `VectorProtocols`, excludes `Reshare`
/// and `ShareKnownValue`.
pub trait BooleanProtocols<C: Context, const N: usize = 1>:
    SecretSharing<Boolean>
    + Reveal<C, N, Output = <Boolean as Vectorizable<N>>::Array>
    + SecureMul<C>
    + Not<Output = Self>
where
    Boolean: FieldSimd<N>,
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>>
    for AdditiveShare<Boolean>
{
}

// Used for aggregation tests
impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, PRF_CHUNK>
    for AdditiveShare<Boolean, PRF_CHUNK>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, AGG_CHUNK>
    for AdditiveShare<Boolean, AGG_CHUNK>
{
}

// Used by semi_honest_compare_gt_vec test.
const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for semi_honest_compare_gt_vec test"
);

// Implementations for num_breakdowns (2^|bk|)
// These are used for aggregate_values and dp noise gen.
const_assert_eq!(
    PRF_CHUNK,
    16,
    "Implementation for N = 16 required for num_breakdowns"
);

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, 32>
    for AdditiveShare<Boolean, 32>
{
}

const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for num_breakdowns"
);
// End implementations for 2^|bk|
