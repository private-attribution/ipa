use crate::{secret_sharing::SharedValue};
use generic_array::ArrayLength;
use std::fmt::Debug;

// Trait for primitive integer types used to represent the underlying type for field values
pub trait Int: Sized + Copy + Debug /* + Into<u128> */ {
    const BITS: u32;
}

impl Int for u8 {
    const BITS: u32 = u8::BITS;
}

impl Int for u32 {
    const BITS: u32 = u32::BITS;
}

pub trait Field: SharedValue + From<u128> + Into<Self::Integer> {
    type Integer: Int;
    type Size: ArrayLength<u8>;

    /// Multiplicative identity element
    const ONE: Self;

    fn as_u128(&self) -> u128;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FieldType {
    Fp31,
    Fp32BitPrime,
}
