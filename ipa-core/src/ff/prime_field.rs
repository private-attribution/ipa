use generic_array::GenericArray;

use super::Field;
use crate::{
    ff::Serializable,
    secret_sharing::{Block, SharedValue},
};

pub trait PrimeField: Field {
    type PrimeInteger: Into<u128>;

    const PRIME: Self::PrimeInteger;
}

impl<F: PrimeField> Serializable for F {
    type Size = <F::Storage as Block>::Size;

    fn serialize(&self, buf: &mut GenericArray<u8, Self::Size>) {
        let raw = &self.as_u128().to_le_bytes()[..buf.len()];
        buf.copy_from_slice(raw);
    }

    fn deserialize(buf: &GenericArray<u8, Self::Size>) -> Self {
        let mut buf_to = [0u8; 16];
        buf_to[..buf.len()].copy_from_slice(buf);

        Self::try_from(u128::from_le_bytes(buf_to)).unwrap()
    }
}

macro_rules! field_impl {
    ( $field:ident, $store:ty, $bits:expr, $prime:expr ) => {
        use super::*;
        use crate::ff::FieldType;

        #[derive(Clone, Copy, PartialEq)]
        pub struct $field(<Self as SharedValue>::Storage);

        impl SharedValue for $field {
            type Storage = $store;
            const BITS: u32 = $bits;
            const ZERO: Self = $field(0);
        }

        impl Field for $field {
            const ONE: Self = $field(1);

            fn as_u128(&self) -> u128 {
                let int: Self::Storage = (*self).into();
                int.into()
            }

            /// An infallible conversion from `u128` to this type.  This can be used to draw
            /// a random value in the field.  This introduces bias into the final value
            /// but for our purposes that bias is small provided that `2^128 >> PRIME`, which
            /// is true provided that `PRIME` is kept to at most 64 bits in value.
            ///
            /// This method is simpler than rejection sampling for these small prime fields.
            fn truncate_from<T: Into<u128>>(v: T) -> Self {
                #[allow(clippy::cast_possible_truncation)]
                Self((v.into() % u128::from(Self::PRIME)) as <Self as SharedValue>::Storage)
            }
        }

        impl PrimeField for $field {
            type PrimeInteger = <Self as SharedValue>::Storage;
            const PRIME: Self::PrimeInteger = $prime;
        }

        impl std::ops::Add for $field {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                let c = u64::from;
                debug_assert!(c(Self::PRIME) < (u64::MAX >> 1));
                Self(((c(self.0) + c(rhs.0)) % c(Self::PRIME)) as <Self as SharedValue>::Storage)
            }
        }

        impl std::ops::AddAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl std::ops::Neg for $field {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self((Self::PRIME - self.0) % Self::PRIME)
            }
        }

        impl std::ops::Sub for $field {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                let c = u64::from;
                debug_assert!(c(Self::PRIME) < (u64::MAX >> 1));
                // TODO(mt) - constant time?
                Self(
                    ((c(Self::PRIME) + c(self.0) - c(rhs.0)) % c(Self::PRIME))
                        as <Self as SharedValue>::Storage,
                )
            }
        }

        impl std::ops::SubAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl std::ops::Mul for $field {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self::Output {
                debug_assert!(u32::try_from(Self::PRIME).is_ok());
                let c = u64::from;
                // TODO(mt) - constant time?
                #[allow(clippy::cast_possible_truncation)]
                Self(((c(self.0) * c(rhs.0)) % c(Self::PRIME)) as <Self as SharedValue>::Storage)
            }
        }

        impl std::ops::MulAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl std::iter::Sum for $field {
            fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
                iter.fold(Self::ZERO, |a, b| a + b)
            }
        }

        impl<'a> std::iter::Sum<&'a $field> for $field {
            fn sum<I: Iterator<Item = &'a Self>>(iter: I) -> Self {
                iter.fold(Self::ZERO, |a, b| a + *b)
            }
        }

        impl TryFrom<u128> for $field {
            type Error = crate::error::Error;

            fn try_from(v: u128) -> Result<Self, Self::Error> {
                if u128::BITS - v.leading_zeros() <= Self::BITS {
                    Ok(Self::truncate_from(v))
                } else {
                    Err(crate::error::Error::FieldValueTruncation(format!(
                        "Storage size {} is too small to hold the value {}.",
                        Self::BITS,
                        v
                    )))
                }
            }
        }

        impl From<$field> for $store {
            fn from(v: $field) -> Self {
                v.0
            }
        }

        impl rand::distributions::Distribution<$field> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $field {
                <$field>::truncate_from(rng.gen::<u128>())
            }
        }

        impl std::fmt::Debug for $field {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}_mod{}", self.0, Self::PRIME)
            }
        }

        #[cfg(any(test, unit_test))]
        impl std::cmp::PartialEq<u128> for $field {
            fn eq(&self, other: &u128) -> bool {
                self.as_u128() == *other
            }
        }

        #[cfg(any(test, unit_test))]
        impl std::cmp::PartialEq<$field> for u128 {
            fn eq(&self, other: &$field) -> bool {
                *self == other.as_u128()
            }
        }

        #[cfg(all(test, unit_test))]
        mod common_tests {
            use generic_array::GenericArray;
            use proptest::proptest;

            use super::*;
            use crate::ff::Serializable;

            #[test]
            fn zero() {
                let prime = u128::from($field::PRIME);
                assert_eq!(
                    $field::ZERO,
                    $field::try_from(prime).unwrap(),
                    "from takes a modulus",
                );
                assert_eq!($field::ZERO, $field::ZERO + $field::ZERO);
                assert_eq!($field::ZERO, $field::ZERO - $field::ZERO);
                assert_eq!(
                    $field::try_from(prime - 1).unwrap(),
                    $field::ZERO - $field::ONE
                );
                assert_eq!($field::ZERO, $field::ZERO * $field::ONE);
            }

            proptest! {

                #[test]
                #[allow(clippy::ignored_unit_patterns)]
                fn serde(v in 0..$field::PRIME) {
                    let field_v = $field(v);
                    let mut buf = GenericArray::default();
                    field_v.serialize(&mut buf);

                    assert_eq!(field_v, $field::deserialize(&buf));
                }
            }
        }

        // Make sure FieldType has a member for this field implementation.
        const _FIELD_TYPE_VALUE: FieldType = crate::ff::FieldType::$field;
    };
}

#[cfg(any(test, feature = "weak-field"))]
mod fp31 {
    field_impl! { Fp31, u8, 8, 31 }

    #[cfg(all(test, unit_test))]
    mod specialized_tests {
        use super::*;

        #[test]
        fn fp31() {
            let x = Fp31(24);
            let y = Fp31(23);

            assert_eq!(Fp31(16), x + y);
            assert_eq!(Fp31(25), x * y);
            assert_eq!(Fp31(1), x - y);

            let mut x = Fp31(1);
            x += Fp31(2);
            assert_eq!(Fp31(3), x);
        }
    }
}

mod fp32bit {
    field_impl! { Fp32BitPrime, u32, 32, 4_294_967_291 }

    #[cfg(all(test, unit_test))]
    mod specialized_tests {
        use super::*;

        #[test]
        fn thirty_two_bit_prime() {
            let x = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::truncate_from(4_294_967_289_u32); // PRIME - 2

            assert_eq!(x - y, Fp32BitPrime::ONE);
            assert_eq!(y - x, Fp32BitPrime::truncate_from(Fp32BitPrime::PRIME - 1));
            assert_eq!(y + x, Fp32BitPrime::truncate_from(Fp32BitPrime::PRIME - 3));

            assert_eq!(x * y, Fp32BitPrime::truncate_from(2_u32),);

            let x = Fp32BitPrime::truncate_from(3_192_725_551_u32);
            let y = Fp32BitPrime::truncate_from(1_471_265_983_u32);

            assert_eq!(x - y, Fp32BitPrime::truncate_from(1_721_459_568_u32));
            assert_eq!(y - x, Fp32BitPrime::truncate_from(2_573_507_723_u32));
            assert_eq!(x + y, Fp32BitPrime::truncate_from(369_024_243_u32));

            assert_eq!(x * y, Fp32BitPrime::truncate_from(513_684_208_u32),);
        }

        #[test]
        fn thirty_two_bit_additive_wrapping() {
            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(20_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(4_u32));

            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(21_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(5_u32));

            let x = Fp32BitPrime::truncate_from(u32::MAX - 20);
            let y = Fp32BitPrime::truncate_from(22_u32);
            assert_eq!(x + y, Fp32BitPrime::truncate_from(6_u32));

            let x = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::truncate_from(4_294_967_290_u32); // PRIME - 1
            assert_eq!(x + y, Fp32BitPrime::truncate_from(4_294_967_289_u32));
        }
    }
}

#[cfg(any(test, feature = "weak-field"))]
pub use fp31::Fp31;
pub use fp32bit::Fp32BitPrime;
