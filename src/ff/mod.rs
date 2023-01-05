// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod prime_field;
use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub use field::{BinaryField, Field, Int};
pub use prime_field::{Fp31, Fp32BitPrime};

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
