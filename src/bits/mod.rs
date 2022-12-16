use std::fmt::Debug;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not};

mod bit_array;

pub use bit_array::BitArray64;

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait BitArray:
    BooleanOps
    + TryFrom<u128>
    + Index<usize>
    + Clone
    + Copy
    + PartialEq
    + Debug
    + Send
    + Sync
    + Sized
    + 'static
{
    /// Size of this data type in bytes. This is the size in memory allocated
    /// for this data type to store the number of bits specified by `BITS`.
    /// `SIZE_IN_BYTES * 8` could be larger than `BITS`, but this type will
    /// store exactly `BITS` number of bits.
    const SIZE_IN_BYTES: usize;
    /// Number of bits stored in this data type.
    const BITS: u32;
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
