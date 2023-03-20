use crate::secret_sharing::{Block, SharedValue};
use std::fmt::Debug;
use typenum::{U1, U4};

impl Block for u8 {
    type Size = U1;
    const VALID_BIT_LENGTH: u32 = u8::BITS;
}

impl Block for u32 {
    type Size = U4;
    const VALID_BIT_LENGTH: u32 = u32::BITS;
}

pub trait Field: SharedValue + From<u128> + Into<Self::Storage> {
    /// Multiplicative identity element
    const ONE: Self;

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FieldType {
    Fp31,
    Fp32BitPrime,
}
