mod into_shares;
mod malicious_replicated;
mod replicated;
mod xor;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;

use crate::bits::BooleanOps;
use crate::ff::{ArithmeticOps, Field};
pub use malicious_replicated::{Downgrade as DowngradeMalicious, MaliciousReplicated};
pub(crate) use malicious_replicated::{
    ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
};
pub use replicated::Replicated;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
pub use xor::XorReplicated;

pub trait SharedValue: Clone + Copy + PartialEq + Debug + Send + Sync + Sized + 'static {
    /// Number of bits stored in this data type.
    const BITS: u32;

    /// Size of this data type in bytes. This is the size in memory allocated
    /// for this data type to store the number of bits specified by `BITS`.
    const SIZE_IN_BYTES: usize;
}

pub trait ArithmeticShare: SharedValue + ArithmeticOps {}

pub trait BooleanShare: SharedValue + BooleanOps {}

impl<T> ArithmeticShare for T where T: SharedValue + ArithmeticOps {}

impl<T> BooleanShare for T where T: SharedValue + BooleanOps {}

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
