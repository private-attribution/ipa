// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod galois_field;
mod prime_field;

use std::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};

pub use field::{Field, FieldType};
pub use galois_field::{GaloisField, Gf2, Gf32Bit, Gf3Bit, Gf40Bit, Gf8Bit};
use generic_array::{ArrayLength, GenericArray};
#[cfg(any(test, feature = "weak-field"))]
pub use prime_field::Fp31;
pub use prime_field::{Fp32BitPrime, PrimeField};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unknown field type {type_str}")]
    UnknownField { type_str: String },
}

/// Arithmetic operations that do not require communication in our MPC setting and can be performed
/// locally.
///
/// Note: Neg operation is also local, but is causing issues when added as a bound to this trait.
/// The problem is that it does not use `Rhs` generic and rustc overflows trying to compile functions
/// that use HRTB generics bounded by `LocalArithmeticOps`.
pub trait LocalArithmeticOps<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + Sized
{
}

impl<T, Rhs, Output> LocalArithmeticOps<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + Sized
{
}

pub trait LocalAssignOps<Rhs = Self>: AddAssign<Rhs> + SubAssign<Rhs> {}
impl<T, Rhs> LocalAssignOps<Rhs> for T where T: AddAssign<Rhs> + SubAssign<Rhs> {}

/// Arithmetic operations that may or may not require communication.
/// for example, multiplying field values is a local operation, while multiplying secret shares is not.
pub trait ArithmeticOps<Rhs = Self, Output = Self>:
    LocalArithmeticOps<Rhs, Output>
    + LocalAssignOps<Rhs>
    + Mul<Rhs, Output = Output>
    + MulAssign<Rhs>
    + Neg<Output = Output>
{
}

impl<T, Rhs, Output> ArithmeticOps<Rhs, Output> for T where
    T: LocalArithmeticOps<Rhs, Output>
        + LocalAssignOps<Rhs>
        + Mul<Rhs, Output = Output>
        + MulAssign<Rhs>
        + Neg<Output = Output>
{
}

/// The trait for references which implement local arithmetic operations, taking the
/// second operand either by value or by reference.
///
/// The need for this trait is dictated by [`rust-issue`] that causes us not being able to constrain
/// references to `Self`. Once this issue is fixed, we can simply get rid of it.
///
/// This is automatically implemented for types which implement the operators. The idea is borrowed
/// from [`RefNum`] trait, but I couldn't really make it work with HRTB and secret shares. Primitive
/// types worked just fine though, so it is possible that it is another compiler issue.
///
/// [`RefNum`]: https://docs.rs/num/0.4.1/num/traits/trait.RefNum.html
/// [`rust-issue`]: https://github.com/rust-lang/rust/issues/20671
pub trait RefOps<'a, Base: 'a, R: 'a>:
    LocalArithmeticOps<Base, Base>
    + LocalArithmeticOps<&'a Base, Base>
    + Mul<R, Output = Base>
    + Mul<&'a R, Output = Base>
{
}
impl<'a, T, Base: 'a, R: 'a> RefOps<'a, Base, R> for T where
    T: LocalArithmeticOps<Base, Base>
        + LocalArithmeticOps<&'a Base, Base>
        + 'a
        + Mul<R, Output = Base>
        + Mul<&'a R, Output = Base>
{
}

/// Trait for items that have fixed-byte length representation.
pub trait Serializable: Sized {
    /// Required number of bytes to store this message on disk/network
    type Size: ArrayLength<u8>;

    /// Serialize this message to a mutable slice. It is enforced at compile time or on the caller
    /// side that this slice is sized to fit this instance. Implementations do not need to check
    /// the buffer size.
    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>);

    /// Deserialize message from a sequence of bytes. Similar to [`serialize`], it is enforced that
    /// buffer has enough capacity to fit instances of this trait.
    ///
    /// [`serialize`]: Self::serialize
    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self;
}
