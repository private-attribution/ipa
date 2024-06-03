pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod reshare;
mod reveal;
mod share_known_value;
pub mod share_validation;
pub mod step;

use std::ops::Not;

pub use check_zero::check_zero;
pub use if_else::select;
pub use mul::{BooleanArrayMul, SecureMul};
pub use reshare::Reshare;
pub use reveal::{partial_reveal, reveal, Reveal};
pub use share_known_value::ShareKnownValue;

use crate::{
    const_assert_eq,
    ff::{boolean::Boolean, PrimeField},
    protocol::{
        context::{
            Context, SemiHonestContext, UpgradedMaliciousContext, UpgradedSemiHonestContext,
        },
        ipa_prf::{AGG_CHUNK, PRF_CHUNK},
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

pub trait BasicProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V>
    + Reshare<C>
    + Reveal<C, N, Output = <V as Vectorizable<N>>::Array>
    + SecureMul<C>
    + ShareKnownValue<C, V>
{
}

pub trait BooleanProtocols<C: Context, const N: usize = 1>:
    SecretSharing<Boolean>
    + Reveal<C, N, Output = <Boolean as Vectorizable<N>>::Array>
    + SecureMul<C>
    + Not<Output = Self>
where
    Boolean: FieldSimd<N>,
{
}

// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<'a, B: ShardBinding, F: PrimeField> BasicProtocols<SemiHonestContext<'a, B>, F>
    for AdditiveShare<F>
{
}

impl<'a, B: ShardBinding, F: PrimeField> BasicProtocols<UpgradedSemiHonestContext<'a, B, F>, F>
    for AdditiveShare<F>
{
}

// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<'a, B: ShardBinding> BooleanProtocols<SemiHonestContext<'a, B>, 1> for AdditiveShare<Boolean> {}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, 1>
    for AdditiveShare<Boolean>
{
}

// Used for aggregation tests
// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<'a, B: ShardBinding> BooleanProtocols<SemiHonestContext<'a, B>, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<C: Context> BooleanProtocols<C, PRF_CHUNK> for AdditiveShare<Boolean, PRF_CHUNK> where
    AdditiveShare<Boolean, PRF_CHUNK>: SecureMul<C>
{
}

impl<C: Context> BooleanProtocols<C, AGG_CHUNK> for AdditiveShare<Boolean, AGG_CHUNK> where
    AdditiveShare<Boolean, AGG_CHUNK>: SecureMul<C>
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

impl<C: Context> BooleanProtocols<C, 32> for AdditiveShare<Boolean, 32> where
    AdditiveShare<Boolean, 32>: SecureMul<C>
{
}

const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for breakdown keys"
);
// End implementations for 2^|bk|

impl<'a, F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousReplicated<F>
{
}
