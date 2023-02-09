use crate::{
    bits::{BooleanOps, Serializable},
    secret_sharing::ArithmeticShare,
};
use generic_array::{ArrayLength, GenericArray};
use std::fmt::Debug;

// Trait for primitive integer types used to represent the underlying type for field values
pub trait Int: Sized + Copy + Debug + Into<u128> {
    const BITS: u32;
}

impl Int for u8 {
    const BITS: u32 = u8::BITS;
}

impl Int for u32 {
    const BITS: u32 = u32::BITS;
}

pub trait Field: ArithmeticShare + From<u128> + Into<Self::Integer> {
    type Integer: Int;
    type Size: ArrayLength<u8>;

    const PRIME: Self::Integer;
    /// Multiplicative identity element
    const ONE: Self;

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128 {
        let int: Self::Integer = (*self).into();
        int.into()
    }
}

impl<F: Field> Serializable for F {
    type Size = <F as Field>::Size;

    fn serialize(self, buf: &mut GenericArray<u8, Self::Size>) {
        let raw = &self.as_u128().to_le_bytes()[..buf.len()];
        buf.copy_from_slice(raw);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mut buf_to = [0u8; 16];
        buf_to[..buf.len()].copy_from_slice(buf);

        Self::from(u128::from_le_bytes(buf_to))
    }
}

pub trait BinaryField: Field + BooleanOps {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub enum FieldType {
    Fp31,
    Fp32BitPrime,
}
