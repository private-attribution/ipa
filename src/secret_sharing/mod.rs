use crate::ff::Field;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};

mod malicious_replicated;
mod replicated;
mod xor;

pub(crate) use malicious_replicated::ThisCodeIsAuthorizedToDowngradeFromMalicious;
pub use malicious_replicated::{Downgrade as DowngradeMalicious, MaliciousReplicated};
pub use replicated::Replicated;
pub use xor::{XorReplicated, XorSecretShare};

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<F>:
    for<'a> Add<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + Mul<F, Output = Self>
    + Clone
    + Debug
    + Sized
    + Send
    + Sync
{
    const ZERO: Self;
}

impl<F: Field> SecretSharing<F> for Replicated<F> {
    const ZERO: Self = Replicated::ZERO;
}
impl<F: Field> SecretSharing<F> for MaliciousReplicated<F> {
    const ZERO: Self = MaliciousReplicated::ZERO;
}
