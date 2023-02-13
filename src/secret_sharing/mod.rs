pub mod replicated;

mod into_shares;
mod scheme;

#[cfg(any(test, feature = "test-fixture", feature = "cli"))]
pub use into_shares::IntoShares;
pub use scheme::{Arithmetic, Boolean, SecretSharing};

use crate::bits::Serializable;
use crate::ff::ArithmeticOps;
use std::fmt::Debug;

pub trait SharedValue:
    Clone + Copy + PartialEq + Debug + Send + Sync + Sized + ArithmeticOps + Serializable + 'static
{
    /// Number of bits stored in this data type.
    const BITS: u32;

    const ZERO: Self;
}
