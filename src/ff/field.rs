use crate::{
    bits::{BooleanOps, Serializable},
    ff::{self, Error},
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

    /// str repr of the type of the [`Field`]; to be used with `FieldType` to get the size of a
    /// given [`Field`] from this value.
    /// # Instruction For Authors
    /// When creating a new [`Field`] type, modify the `FieldType::serialize` and
    /// `FieldType::deserialize` functions below this trait definition to use the newly created
    /// type
    const TYPE_STR: &'static str;

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

    fn deserialize(buf: GenericArray<u8, Self::Size>) -> Self {
        let mut buf_to = [0u8; 16];
        buf_to[..buf.len()].copy_from_slice(&buf);

        Self::from(u128::from_le_bytes(buf_to))
    }
}

pub trait BinaryField: Field + BooleanOps {}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FieldType {
    Fp31,
    Fp32BitPrime,
}

impl AsRef<str> for FieldType {
    fn as_ref(&self) -> &str {
        match self {
            FieldType::Fp31 => ff::Fp31::TYPE_STR,
            FieldType::Fp32BitPrime => ff::Fp32BitPrime::TYPE_STR,
        }
    }
}

/// For Authors: when adding a new [`Field`] type, add it to the `serialize` fn below
#[cfg(feature = "enable-serde")]
impl serde::Serialize for FieldType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_ref())
    }
}

/// For Authors: when adding a new [`Field`] type, add it to the `visit_str` fn below
#[cfg(feature = "enable-serde")]
impl<'de> serde::Deserialize<'de> for FieldType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct FieldTypeVisitor;
        impl<'de> serde::de::Visitor<'de> for FieldTypeVisitor {
            type Value = FieldType;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a correctly formatted FieldType")
            }

            fn visit_str<E: serde::de::Error>(
                self,
                field_type_str: &str,
            ) -> Result<Self::Value, E> {
                if field_type_str.eq_ignore_ascii_case(ff::Fp31::TYPE_STR) {
                    Ok(FieldType::Fp31)
                } else if field_type_str.eq_ignore_ascii_case(ff::Fp32BitPrime::TYPE_STR) {
                    Ok(FieldType::Fp32BitPrime)
                } else {
                    Err(serde::de::Error::custom(Error::UnknownField {
                        type_str: field_type_str.to_string(),
                    }))
                }
            }

            fn visit_string<E: serde::de::Error>(
                self,
                field_type_str: String,
            ) -> Result<Self::Value, E> {
                self.visit_str(&field_type_str)
            }
        }
        deserializer.deserialize_str(FieldTypeVisitor)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "enable-serde")]
    #[test]
    fn field_type_str_is_case_insensitive() {
        let field_type: FieldType = serde_json::from_str("\"fP32bItPrImE\"")
            .expect("FieldType should match regardless of character case");
        assert_eq!(field_type, FieldType::Fp32BitPrime);
    }
}
