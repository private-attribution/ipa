pub mod replicated;

mod into_shares;
mod scheme;

use generic_array::ArrayLength;
#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;
pub use scheme::{Bitwise, Linear, SecretSharing};

use crate::ff::{ArithmeticOps, Serializable};
use std::fmt::Debug;

// Trait for primitive integer types used to represent the underlying type for shared values
pub trait Block: Sized + Copy + Debug {
    /// Size of a block in bytes big enough to hold the shared value. `Size * 8 >= VALID_BIT_LENGTH`.
    type Size: ArrayLength<u8>;
}

pub trait SharedValue:
    Clone + Copy + PartialEq + Debug + Send + Sync + Sized + ArithmeticOps + Serializable + 'static
{
    type Storage: Block;

    const BITS: u32;

    const ZERO: Self;
}
