pub mod apply_permutation;
#[cfg(feature = "descriptive-gate")]
pub mod check_zero;
mod if_else;
pub(crate) mod mul;
mod partial_reveal;
mod reshare;
mod reveal;
mod share_known_value;
pub mod sum_of_product;

#[cfg(feature = "descriptive-gate")]
pub use check_zero::check_zero;
pub use if_else::if_else;
pub use mul::{MultiplyZeroPositions, SecureMul, ZeroPositions};
pub use partial_reveal::PartialReveal;
pub use reshare::Reshare;
pub use reveal::Reveal;
pub use share_known_value::ShareKnownValue;
pub use sum_of_product::SumOfProducts;

#[cfg(feature = "descriptive-gate")]
use crate::protocol::context::UpgradedMaliciousContext;
use crate::{
    ff::Field,
    protocol::{context::Context, RecordId},
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousAdditiveShare, ExtendableField},
            semi_honest::AdditiveShare,
        },
        SecretSharing, SharedValue,
    },
};

pub trait BasicProtocols<C: Context, V: SharedValue>:
    SecretSharing<V>
    + Reshare<C, RecordId>
    + Reveal<C, RecordId, Output = V>
    + SecureMul<C>
    + ShareKnownValue<C, V>
    + SumOfProducts<C>
{
}

impl<C: Context, F: Field> BasicProtocols<C, F> for AdditiveShare<F> {}

#[cfg(feature = "descriptive-gate")]
impl<'a, F: ExtendableField> BasicProtocols<UpgradedMaliciousContext<'a, F>, F>
    for MaliciousAdditiveShare<F>
{
}
