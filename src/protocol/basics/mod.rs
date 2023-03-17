pub(crate) mod check_zero;
pub(crate) mod mul;
pub(crate) mod reshare;
pub(crate) mod reveal;
pub(crate) mod share_known_value;
pub(crate) mod sum_of_product;

pub use check_zero::check_zero;
pub use mul::{MultiplyZeroPositions, SecureMul, ZeroPositions};
pub use reshare::Reshare;
pub use reveal::Reveal;
pub use share_known_value::ShareKnownValue;
pub use sum_of_product::SumOfProducts;

use crate::{
    ff::Field,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousAdditiveShare, ExtendableField}, semi_honest::AdditiveShare,
        },
        SharedValue,
    },
};

pub trait BasicProtocols<C: Context, V: SharedValue>:
    Reshare<C, RecordId>
    + Reveal<C, RecordId, Output = V>
    + SecureMul<C>
    + ShareKnownValue<C, V>
    + SumOfProducts<C>
{
}

impl<'a, F: Field> BasicProtocols<SemiHonestContext<'a>, F> for AdditiveShare<F> {}

impl<'a, F: Field + ExtendableField> BasicProtocols<MaliciousContext<'a, F>, F> for MaliciousAdditiveShare<F> {}
