use crate::secret_sharing::BooleanShare;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not};

mod bit_array;

pub use bit_array::BitArray64;

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait BitArray: BooleanShare + TryFrom<u128> + Index<usize> {
    /// A bit array with all its elements initialized to 0.
    const ZERO: Self;

    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;
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
