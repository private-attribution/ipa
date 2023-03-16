// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod field;
mod galois_field;
mod prime_field;

pub use field::{Field, FieldType, Int};
pub use galois_field::{Gf40Bit, Gf8Bit};
pub use prime_field::{Fp31, Fp32BitPrime, PrimeField};

use crate::secret_sharing::SharedValue;
use generic_array::{ArrayLength, GenericArray};
use std::ops::{Add, AddAssign, Index, Mul, MulAssign, Neg, Sub, SubAssign};

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

pub trait ArithmeticRefOps<V: SharedValue>:
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
    V: SharedValue,
{
}

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait GaloisField:
    SharedValue + TryFrom<u128> + Into<u128> + Index<usize, Output = bool> + Index<u32, Output = bool>
{
    const POLYNOMIAL: u128;

    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;

    fn as_u128(self) -> u128 {
        <Self as Into<u128>>::into(self)
    }
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
