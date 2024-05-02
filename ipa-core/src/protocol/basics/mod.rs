pub mod apply_permutation;
#[cfg(feature = "descriptive-gate")]
pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod reshare;
mod reveal;
mod share_known_value;
pub mod sum_of_product;

use std::ops::Not;

#[cfg(feature = "descriptive-gate")]
pub use check_zero::check_zero;
pub use if_else::{if_else, select};
pub use mul::{BooleanArrayMul, MultiplyZeroPositions, SecureMul, ZeroPositions};
pub use reshare::Reshare;
pub use reveal::{partial_reveal, reveal, Reveal};
pub use share_known_value::ShareKnownValue;
pub use sum_of_product::SumOfProducts;

use crate::{
    const_assert_eq,
    ff::{boolean::Boolean, PrimeField},
    protocol::{
        context::{Context, SemiHonestContext, UpgradedSemiHonestContext},
        ipa_prf::{AGG_CHUNK, PRF_CHUNK},
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, SecretSharing, SharedValue, Vectorizable,
    },
    sharding::ShardBinding,
};
#[cfg(feature = "descriptive-gate")]
use crate::{
    protocol::context::UpgradedMaliciousContext,
    secret_sharing::replicated::malicious::{
        AdditiveShare as MaliciousReplicated, ExtendableField,
    },
};

pub trait BasicProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V>
    + Reshare<C>
    + Reveal<C, N, Output = <V as Vectorizable<N>>::Array>
    + SecureMul<C>
    + ShareKnownValue<C, V>
    + SumOfProducts<C>
{
}

pub trait BooleanProtocols<C: Context, V: SharedValue + Vectorizable<N>, const N: usize = 1>:
    SecretSharing<V>
    + Reveal<C, N, Output = <V as Vectorizable<N>>::Array>
    + SecureMul<C>
    + Not<Output = Self>
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
impl<'a, B: ShardBinding> BooleanProtocols<SemiHonestContext<'a, B>, Boolean, 1>
    for AdditiveShare<Boolean>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, Boolean, 1>
    for AdditiveShare<Boolean>
{
}

// Used for aggregation tests
// TODO: It might be better to remove this (protocols should use upgraded contexts)
impl<'a, B: ShardBinding> BooleanProtocols<SemiHonestContext<'a, B>, Boolean, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<'a, B: ShardBinding> BooleanProtocols<UpgradedSemiHonestContext<'a, B, Boolean>, Boolean, 8>
    for AdditiveShare<Boolean, 8>
{
}

impl<C: Context> BooleanProtocols<C, Boolean, PRF_CHUNK> for AdditiveShare<Boolean, PRF_CHUNK> where
    AdditiveShare<Boolean, PRF_CHUNK>: SecureMul<C>
{
}

// Used by semi_honest_compare_gt_vec test.
impl<C: Context> BooleanProtocols<C, Boolean, AGG_CHUNK> for AdditiveShare<Boolean, AGG_CHUNK> where
    AdditiveShare<Boolean, AGG_CHUNK>: SecureMul<C>
{
}

const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for semi_honest_compare_gt_vec test"
);

// Implementations for 2^|bk|
impl<C: Context> BooleanProtocols<C, Boolean, 32> for AdditiveShare<Boolean, 32> where
    AdditiveShare<Boolean, 32>: SecureMul<C>
{
}

const_assert_eq!(
    AGG_CHUNK,
    256,
    "Implementation for N = 256 required for breakdown keys"
);
// End implementations for 2^|bk|

#[cfg(feature = "descriptive-gate")]
impl<'a, F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousReplicated<F>
{
}
