// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;

pub use field::{BinaryField, Field, FieldType, Int};
pub use prime_field::{Fp2, Fp31, Fp32BitPrime};

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
