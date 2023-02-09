// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;

pub use field::{BinaryField, Field, FieldType, Int};
pub use prime_field::{Fp31, Fp32BitPrime};

use crate::secret_sharing::ArithmeticShare;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unknown field type {type_str}")]
    UnknownField { type_str: String },
}

pub trait ArithmeticOps:
    Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + Neg<Output = Self>
    + Sized
{
}

impl<T> ArithmeticOps for T where
    T: Add<Output = Self>
        + AddAssign
        + Sub<Output = Self>
        + SubAssign
        + Mul<Output = Self>
        + MulAssign
        + Neg<Output = Self>
        + Sized
{
}

pub trait ArithmeticRefOps<V: ArithmeticShare>:
    for<'a> Add<&'a Self, Output = Self>
    + for<'a> AddAssign<&'a Self>
    + Neg<Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
    + for<'a> SubAssign<&'a Self>
    + Mul<V, Output = Self>
{
}

impl<T, V> ArithmeticRefOps<V> for T
where
    T: for<'a> Add<&'a Self, Output = Self>
        + for<'a> AddAssign<&'a Self>
        + Neg<Output = Self>
        + for<'a> Sub<&'a Self, Output = Self>
        + for<'a> SubAssign<&'a Self>
        + Mul<V, Output = Self>,
    V: ArithmeticShare,
{
}
