// ff - Finite Fields
//
// This is where we store arithmetic shared secret data models.

mod accumulator;
pub mod boolean;
pub mod boolean_array;
pub mod curve_points;
pub mod ec_prime_field;
mod field;
mod galois_field;
mod prime_field;

use std::{
    convert::Infallible,
    ops::{Add, AddAssign, Sub, SubAssign},
};

pub use accumulator::{MultiplyAccumulate, MultiplyAccumulator, MultiplyAccumulatorArray};
pub use field::{Field, FieldType};
pub use galois_field::{GaloisField, Gf2, Gf20Bit, Gf32Bit, Gf3Bit, Gf40Bit, Gf8Bit, Gf9Bit};
use generic_array::{ArrayLength, GenericArray};
#[cfg(any(test, feature = "weak-field"))]
pub use prime_field::Fp31;
pub use prime_field::{batch_invert, Fp32BitPrime, Fp61BitPrime, PrimeField};

use crate::{
    error::UnwrapInfallible, protocol::prss::FromRandomU128, secret_sharing::BitDecomposed,
};

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

pub trait U128Conversions: FromRandomU128 + TryFrom<u128, Error = crate::error::Error> {
    /// Truncates higher-order bits and converts into this data type. This conversion is lossy if
    /// the higher order bits are non-zero. Callers are encouraged to use `try_from` if the input may
    /// not be convertible.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    fn as_u128(&self) -> u128;
}

/// Trait for items that have fixed-byte length representation.
pub trait Serializable: Sized {
    /// Required number of bytes to store this message on disk/network
    type Size: ArrayLength;
    /// The error type that can be returned if an error occurs during deserialization.
    type DeserializationError: std::error::Error + Send + Sync + 'static;

    /// Serialize this message to a mutable slice. It is enforced at compile time or on the caller
    /// side that this slice is sized to fit this instance. Implementations do not need to check
    /// the buffer size.
    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>);

    /// Deserialize message from a sequence of bytes. Similar to [`serialize`], it is enforced that
    /// buffer has enough capacity to fit instances of this trait.
    ///
    /// [`serialize`]: Self::serialize
    ///
    /// ## Errors
    /// In general, deserialization may fail even if buffer size is enough. The bytes may
    /// not represent a valid value in the domain, in this case implementations will return an error.
    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Result<Self, Self::DeserializationError>;

    /// Same as [`deserialize`] but returns an actual value if it is known at compile time that deserialization
    /// is infallible.
    ///
    /// [`deserialize`]: Self::deserialize
    fn deserialize_infallible(buf: &GenericArray<u8, Self::Size>) -> Self
    where
        Infallible: From<Self::DeserializationError>,
    {
        Self::deserialize(buf)
            .map_err(Into::into)
            .unwrap_infallible()
    }

    /// This method provides the same functionality as [`Self::deserialize`] without
    /// compile-time guarantees on the size of `buf`. Therefore, it is not appropriate
    /// to use in production code. It is provided as convenience method
    /// for tests that are ok to panic.
    ///
    /// ## Panics
    /// If the size of `buf` is not equal to `Self::Size` or if `buf` bytes
    /// are not a valid representation of this instance. See [`Self::deserialize`] for
    /// more details.
    ///
    /// [`Self::deserialize`]: Self::deserialize
    #[cfg(test)]
    #[must_use]
    fn deserialize_from_slice(buf: &[u8]) -> Self {
        use typenum::Unsigned;

        assert_eq!(buf.len(), Self::Size::USIZE);

        let mut arr = GenericArray::default();
        arr.copy_from_slice(buf);
        Self::deserialize(&arr).unwrap()
    }

    /// This method provides the same functionality as [`Self::serialize`] without
    /// compile-time guarantees on the size of `buf`. Therefore, it is not appropriate
    /// to use in production code. It is provided as convenience method
    /// for tests that are ok to panic.
    ///
    /// ## Panics
    /// If the size of `buf` is not equal to `Self::Size`.
    #[cfg(test)]
    fn serialize_to_slice(&self, buf: &mut [u8]) {
        use typenum::Unsigned;

        assert_eq!(buf.len(), Self::Size::USIZE);

        let dest = GenericArray::<_, Self::Size>::from_mut_slice(buf);
        self.serialize(dest);
    }
}

pub trait ArrayAccess {
    type Output;
    type Iter<'a>: ExactSizeIterator<Item = Self::Output> + Send
    where
        Self: 'a;

    fn get(&self, index: usize) -> Option<Self::Output>;

    fn set(&mut self, index: usize, e: Self::Output);

    fn iter(&self) -> Self::Iter<'_>;

    fn to_bits(&self) -> BitDecomposed<Self::Output> {
        BitDecomposed::new(self.iter())
    }
}

pub trait Expand<T> {
    fn expand(v: &T) -> Self;
}
