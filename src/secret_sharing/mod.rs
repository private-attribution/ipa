mod into_shares;
pub mod replicated;
mod scheme;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;

pub use scheme::{Arithmetic, Boolean, SecretSharing};

use crate::bits::BooleanOps;
use crate::ff::ArithmeticOps;
use std::fmt::Debug;

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
