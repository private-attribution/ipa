use std::fmt::Debug;

use typenum::{U1, U4};

use crate::{
    error,
    secret_sharing::{Block, SharedValue},
};

impl Block for u8 {
    type Size = U1;
}

impl Block for u32 {
    type Size = U4;
}

pub trait Field: SharedValue + TryFrom<u128, Error = error::Error> + Into<Self::Storage> {
    /// Multiplicative identity element
    const ONE: Self;

    /// Truncates the higher-order bits larger than `Self::BITS`, and converts
    /// into this data type. This conversion is lossy. Callers are encouraged
    /// to use `try_from` if the input is not known in advance.
    fn truncate_from<T: Into<u128>>(v: T) -> Self;

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "clap", derive(clap::ValueEnum))]
pub enum FieldType {
    #[cfg(any(test, feature = "weak-field"))]
    Fp31,
    Fp32BitPrime,
}
