mod malicious_replicated;
mod replicated;

use crate::ff::Field;
pub use malicious_replicated::MaliciousReplicated;
pub use replicated::Replicated;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<F>:
    Add + AddAssign + Neg + Sub + SubAssign + Mul<F> + Debug + Sized
{
}

impl<F: Field> SecretSharing<F> for Replicated<F> {}
impl<F: Field> SecretSharing<F> for MaliciousReplicated<F> {}
