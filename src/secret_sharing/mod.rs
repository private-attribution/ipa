mod malicious_replicated;
mod replicated;

use crate::ff::Field;
pub use malicious_replicated::MaliciousReplicated;
pub use replicated::Replicated;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<F>:
    for<'a> Add<&'a Self>
    + for<'a> AddAssign<&'a Self>
    + Neg
    + for<'a> Sub<&'a Self>
    + for<'a> SubAssign<&'a Self>
    + Mul<F>
    + Debug
    + Default
    + Sized
    + Sync
{
}

impl<F: Field> SecretSharing<F> for Replicated<F> {}
impl<F: Field> SecretSharing<F> for MaliciousReplicated<F> {}
