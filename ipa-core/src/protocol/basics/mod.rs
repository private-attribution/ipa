pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod reshare;
mod reveal;
#[allow(dead_code)]
mod shard_fin;
mod share_known_value;
pub mod share_validation;
pub mod step;

use std::ops::Not;

pub use if_else::select;
pub use mul::{BooleanArrayMul, SecureMul};
pub use reshare::Reshare;
pub use reveal::{
    malicious_reveal, partial_reveal, reveal, semi_honest_reveal, validated_partial_reveal, Reveal,
};
pub use share_known_value::ShareKnownValue;

use crate::{
    const_assert_eq,
    ff::{boolean::Boolean, ec_prime_field::Fp25519, PrimeField},
    protocol::{
        context::{
            Context, DZKPUpgradedMaliciousContext, DZKPUpgradedSemiHonestContext,
            UpgradedMaliciousContext, UpgradedSemiHonestContext,
        },
        ipa_prf::{AGG_CHUNK, PRF_CHUNK},
        prss::FromPrss,
    },
    secret_sharing::{
        replicated::{malicious, semi_honest::AdditiveShare},
        FieldSimd, SecretSharing, SharedValue, Vectorizable,
    },
    sharding::ShardBinding,
};

/// Basic suite of MPC protocols for vectorized data.
///
/// A previous version of `BasicProtocols` additionally required `Reshare` and `ShareKnownValue`,
/// but those are omitted here because they are not vectorized. (`ShareKnownValue` has the
/// difficulty of resolving `V` vs. `[V; 1]` issues for the known value type. `Reshare` hasn't been
/// attempted.)
pub trait BasicProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V> + Reveal<C, Output = <V as Vectorizable<N>>::Array> + SecureMul<C>
{
}

// For PRF test
impl<'a, B: ShardBinding> BasicProtocols<UpgradedSemiHonestContext<'a, B, Fp25519>, Fp25519>
    for AdditiveShare<Fp25519>
{
}

impl<'a, B: ShardBinding>
    BasicProtocols<UpgradedSemiHonestContext<'a, B, Fp25519>, Fp25519, PRF_CHUNK>
    for AdditiveShare<Fp25519, PRF_CHUNK>
{
}

impl<'a, const N: usize> BasicProtocols<UpgradedMaliciousContext<'a, Fp25519>, Fp25519, N>
    for malicious::AdditiveShare<Fp25519, N>
where
    Fp25519: FieldSimd<N>,
    AdditiveShare<Fp25519, N>: FromPrss,
{
}

/// Basic suite of MPC protocols for (possibly vectorized) boolean shares.
///
/// Adds the requirement that the type implements `Not`.
pub trait BooleanProtocols<C: Context, const N: usize = 1>:
    SecretSharing<Boolean>
    + Reveal<C, Output = <Boolean as Vectorizable<N>>::Array>
    + SecureMul<C>
    + Not<Output = Self>
where
    Boolean: FieldSimd<N>,
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>>
    for AdditiveShare<Boolean>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedMaliciousContext<'a, B>>
    for AdditiveShare<Boolean>
{
}

// Used for aggregation tests
impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>, PRF_CHUNK>
    for AdditiveShare<Boolean, PRF_CHUNK>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedMaliciousContext<'a, B>, PRF_CHUNK>
    for AdditiveShare<Boolean, PRF_CHUNK>
{
}

// These implementations also implement `BooleanProtocols` for `CONV_CHUNK`
// since `CONV_CHUNK = AGG_CHUNK`
impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>, AGG_CHUNK>
    for AdditiveShare<Boolean, AGG_CHUNK>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedMaliciousContext<'a, B>, AGG_CHUNK>
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

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>, 3>
    for AdditiveShare<Boolean, 3>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedSemiHonestContext<'a, B>, 32>
    for AdditiveShare<Boolean, 32>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<DZKPUpgradedMaliciousContext<'a, B>, 32>
    for AdditiveShare<Boolean, 32>
{
}

const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for num_breakdowns"
);
// End implementations for num_breakdowns
