mod into_shares;
mod malicious_replicated;
mod replicated;
mod xor;
#[cfg(any(feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;

use crate::ff::Field;
pub use malicious_replicated::{Downgrade as DowngradeMalicious, MaliciousReplicated};
pub(crate) use malicious_replicated::{
    ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
};
pub use replicated::Replicated;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
pub use xor::XorReplicated;

pub trait SharedValue: Clone + Copy + PartialEq + Debug + Send + Sync + Sized + 'static {}

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<V: SharedValue>:
    for<'a> Add<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + Mul<V, Output = Self>
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
