mod into_shares;
pub mod replicated;
mod xor;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;

use crate::bits::BooleanOps;
use crate::ff::ArithmeticOps;
use std::fmt::Debug;
use std::ops::{Add, AddAssign, Mul, Neg, Sub, SubAssign};
pub use xor::XorReplicated;

use self::replicated::malicious::AdditiveShare as MaliciousAdditiveShare;
use self::replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare;

pub trait SharedValue: Clone + Copy + PartialEq + Debug + Send + Sync + Sized + 'static {
    /// Number of bits stored in this data type.
    const BITS: u32;

    /// Size of this data type in bytes. This is the size in memory allocated
    /// for this data type to store the number of bits specified by `BITS`.
    /// TODO(alex): replace with Serializable
    const SIZE_IN_BYTES: usize;

    const ZERO: Self;
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

impl<V: ArithmeticShare> SecretSharing<V> for SemiHonestAdditiveShare<V> {
    const ZERO: Self = SemiHonestAdditiveShare::ZERO;
}
impl<V: ArithmeticShare> SecretSharing<V> for MaliciousAdditiveShare<V> {
    const ZERO: Self = MaliciousAdditiveShare::ZERO;
}
