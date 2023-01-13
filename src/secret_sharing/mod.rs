mod into_shares;
pub mod replicated;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;

use crate::bits::{BooleanOps, BooleanRefOps};
use crate::ff::{ArithmeticOps, ArithmeticRefOps};
use std::fmt::Debug;

use self::replicated::malicious::AdditiveShare as MaliciousAdditiveShare;
use self::replicated::semi_honest::AdditiveShare as SemiHonestAdditiveShare;
use self::replicated::semi_honest::XorShare as SemiHonestXorShare;

pub trait SharedValue: Clone + Copy + PartialEq + Debug + Send + Sync + Sized + 'static {
    /// Number of bits stored in this data type.
    const BITS: u32;

    /// Size of this data type in bytes. This is the size in memory allocated
    /// for this data type to store the number of bits specified by `BITS`.
    const SIZE_IN_BYTES: usize;

    const ZERO: Self;
}

pub trait ArithmeticShare: SharedValue + ArithmeticOps {}

pub trait BooleanShare: SharedValue + BooleanOps {}

impl<T> ArithmeticShare for T where T: SharedValue + ArithmeticOps {}

impl<T> BooleanShare for T where T: SharedValue + BooleanOps {}

/// Secret share of a secret has additive and multiplicative properties.
pub trait SecretSharing<V: SharedValue>: Clone + Debug + Sized + Send + Sync {
    const ZERO: Self;
}

impl<V: ArithmeticShare> SecretSharing<V> for SemiHonestAdditiveShare<V> {
    const ZERO: Self = SemiHonestAdditiveShare::ZERO;
}
impl<V: ArithmeticShare> SecretSharing<V> for MaliciousAdditiveShare<V> {
    const ZERO: Self = MaliciousAdditiveShare::ZERO;
}
impl<V: BooleanShare> SecretSharing<V> for SemiHonestXorShare<V> {
    const ZERO: Self = SemiHonestXorShare::ZERO;
}

pub trait ArithmeticSecretSharing<V: ArithmeticShare>:
    SecretSharing<V> + ArithmeticRefOps<V>
{
}

pub trait BooleanSecretSharing<V: BooleanShare>: SecretSharing<V> + BooleanRefOps {}

impl<V: ArithmeticShare> ArithmeticSecretSharing<V> for SemiHonestAdditiveShare<V> {}
impl<V: ArithmeticShare> ArithmeticSecretSharing<V> for MaliciousAdditiveShare<V> {}
impl<V: BooleanShare> BooleanSecretSharing<V> for SemiHonestXorShare<V> {}
