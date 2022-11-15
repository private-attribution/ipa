mod malicious_replicated;
mod replicated;

use crate::ff::Field;
use crate::helpers::Role;
pub use malicious_replicated::MaliciousReplicated;
pub use replicated::Replicated;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<F>:
    Add + AddAssign + Default + Neg + Sub + SubAssign + Mul<F> + Debug + Sized + Sub<Output = Self>
{
    fn one(helper_role: Role, r_share: Replicated<F>) -> Self;
}

impl<F: Field> SecretSharing<F> for Replicated<F> {
    /// Returns share of value one.
    fn one(helper_role: Role, _: Replicated<F>) -> Self {
        match helper_role {
            Role::H1 => Self::new(F::ONE, F::ZERO),
            Role::H2 => Self::new(F::ZERO, F::ZERO),
            Role::H3 => Self::new(F::ZERO, F::ONE),
        }
    }
}
impl<F: Field> SecretSharing<F> for MaliciousReplicated<F> {
    /// Returns a pair of replicated secret sharings. One of "one", one of "r"
    fn one(helper_role: Role, r_share: Replicated<F>) -> Self {
        Self::new(Replicated::one(helper_role, r_share), r_share)
    }
}
