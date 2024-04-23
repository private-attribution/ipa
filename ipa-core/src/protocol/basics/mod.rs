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
    ff::{boolean::Boolean, Field},
    protocol::{context::Context, ipa_prf::PRF_CHUNK},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, SecretSharing, SharedValue, Vectorizable,
    },
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

impl<C: Context, F: Field> BasicProtocols<C, F> for AdditiveShare<F> {}

impl<C: Context> BooleanProtocols<C, Boolean, 1> for AdditiveShare<Boolean> {}

impl<C: Context> BooleanProtocols<C, Boolean, PRF_CHUNK> for AdditiveShare<Boolean, PRF_CHUNK> {}

// Used by semi_honest_compare_gt_vec test.
impl<C: Context> BooleanProtocols<C, Boolean, 256> for AdditiveShare<Boolean, 256> {}

#[cfg(feature = "descriptive-gate")]
impl<'a, F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousReplicated<F>
{
}
