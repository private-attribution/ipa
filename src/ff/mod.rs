// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

pub mod boolean;
pub mod boolean_array;
pub mod curve_points;
pub mod ec_prime_field;
mod field;
mod galois_field;
mod prime_field;

use std::ops::{Add, AddAssign, Sub, SubAssign};

pub use field::{Field, FieldType};
pub use galois_field::{GaloisField, Gf2, Gf32Bit, Gf3Bit, Gf40Bit, Gf5Bit, Gf8Bit};
use generic_array::{ArrayLength, GenericArray};
#[cfg(any(test, feature = "weak-field"))]
pub use prime_field::Fp31;
pub use prime_field::{Fp32BitPrime, PrimeField};
use crate::secret_sharing::WeakSharedValue;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("unknown field type {type_str}")]
    UnknownField { type_str: String },
}

/// Addition and subtraction operations that are supported by secret sharings and shared values.
pub trait AddSub<Rhs = Self, Output = Self>:
    Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + Sized
{
}

impl<T, Rhs, Output> AddSub<Rhs, Output> for T where
    T: Add<Rhs, Output = Output> + Sub<Rhs, Output = Output> + Sized
{
}

pub trait AddSubAssign<Rhs = Self>: AddAssign<Rhs> + SubAssign<Rhs> {}
impl<T, Rhs> AddSubAssign<Rhs> for T where T: AddAssign<Rhs> + SubAssign<Rhs> {}

/// Trait for items that have fixed-byte length representation.
pub trait Serializable: Sized {
    /// Required number of bytes to store this message on disk/network
    type Size: ArrayLength;

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

pub trait ArrayAccess {
    type AAElement;

    fn get(&self, index: usize) -> Option<Self::AAElement>;

    fn set(&mut self, index: usize, e: Self::AAElement);
}

/// Custom Array trait
/// supports access to elements via `ArrayAccess` and functions `get(Index: usize)` and `set(Index: usize, v: Element)`
/// doesn't support `IntoIterator` and `into_iter()`, &'a S: IntoIterator<Item= S::Element> needs to be added manually in trait bound when used
/// supports `From` for `Element`, all array elements will be set to the value of `Element`
/// supports `FromIterator` to collect an iterator of elements back into the original type
pub trait CustomArray
    where
        Self: WeakSharedValue + ArrayAccess<AAElement=Self::Element>
        + From<Self::Element>
        + FromIterator<Self::Element>,
        //&'a Self: IntoIterator<Item = T>,
        Self::Element: WeakSharedValue,
{
    type Element;
}

/// impl Custom Array for all compatible structs
impl<S> CustomArray for S where
    S: WeakSharedValue + ArrayAccess + From<Self::AAElement> + FromIterator<Self::AAElement> ,
    Self::AAElement: WeakSharedValue,
{
    type Element = <S as ArrayAccess>::AAElement;
}
