use std::fmt::Debug;
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Index, Not};

mod bit_array;

pub use bit_array::BitArray64;

/// Trait for data types storing arbitrary number of bits.
// TODO: Implement `Message`
pub trait BitArray:
    BooleanOps
    + From<u128>
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
    const SIZE_IN_BYTES: usize;
    const ZERO: Self;
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
