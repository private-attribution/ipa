use crate::secret_sharing::BooleanShare;

use generic_array::{ArrayLength, GenericArray};

use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not};

mod bit_array;

pub use bit_array::{BitArray40, BitArray8};

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait BitArray:
    BooleanShare + TryFrom<u128> + Into<u128> + Index<usize, Output = bool> + Index<u32, Output = bool>
{
    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;

    fn as_u128(self) -> u128 {
        <Self as Into<u128>>::into(self)
    }
}

pub trait BooleanOps:
    BitAnd<Output = Self>
    + BitAndAssign
    + BitOr<Output = Self>
    + BitOrAssign
    + BitXor<Output = Self>
    + BitXorAssign
    + Not<Output = Self>
    + Sized
{
}

impl<T> BooleanOps for T where
    T: BitAnd<Output = Self>
        + BitAndAssign
        + BitOr<Output = Self>
        + BitOrAssign
        + BitXor<Output = Self>
        + BitXorAssign
        + Not<Output = Self>
        + Sized
{
}

pub trait BooleanRefOps:
    for<'a> BitXor<&'a Self, Output = Self> + for<'a> BitXorAssign<&'a Self>
{
}

impl<T> BooleanRefOps for T where
    T: for<'a> BitXor<&'a Self, Output = Self> + for<'a> BitXorAssign<&'a Self>
{
}

/// Trait for items that have fixed-byte length representation.
pub trait Serializable: Sized {
    /// Required number of bytes to store this message on disk/network
    type Size: ArrayLength<u8>;

    /// Serialize this message to a mutable slice. It is enforced at compile time or on the caller
    /// side that this slice is sized to fit this instance. Implementations do not need to check
    /// the buffer size.
    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>);

    /// Deserialize message from a sequence of bytes. Similar to [`serialize`], it is enforced that
    /// buffer has enough capacity to fit instances of this trait.
    ///
    /// [`serialize`]: Self::serialize
    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self;
}
