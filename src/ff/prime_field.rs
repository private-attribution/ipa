use super::Field;
use crate::secret_sharing::SharedValue;

macro_rules! field_impl {
    ( $field:ident, $int:ty, $prime:expr, $arraylen:ty ) => {
        use super::*;
        use crate::ff::FieldType;

        #[derive(Clone, Copy, PartialEq)]
        pub struct $field(<Self as Field>::Integer);

        impl Field for $field {
            type Integer = $int;
            type Size = $arraylen;
            const PRIME: Self::Integer = $prime;
            const ONE: Self = $field(1);
        }

        impl SharedValue for $field {
            const BITS: u32 = <Self as Field>::Integer::BITS;
            const ZERO: Self = $field(0);
        }

        impl std::ops::Add for $field {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                let c = u64::from;
                debug_assert!(c(Self::PRIME) < (u64::MAX >> 1));
                Self(((c(self.0) + c(rhs.0)) % c(Self::PRIME)) as <Self as Field>::Integer)
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
                        as <Self as Field>::Integer,
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
                Self(((c(self.0) * c(rhs.0)) % c(Self::PRIME)) as <Self as Field>::Integer)
            }
        }

        impl std::ops::MulAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        /// An infallible conversion from `u128` to this type.  This can be used to draw
        /// a random value in the field.  This introduces bias into the final value
        /// but for our purposes that bias is small provided that `2^128 >> PRIME`, which
        /// is true provided that `PRIME` is kept to at most 64 bits in value.
        ///
        /// This method is simpler than rejection sampling for these small prime fields.
        impl<T: Into<u128>> From<T> for $field {
            fn from(v: T) -> Self {
                #[allow(clippy::cast_possible_truncation)]
                Self((v.into() % u128::from(Self::PRIME)) as <Self as Field>::Integer)
            }
        }

        impl From<$field> for $int {
            fn from(v: $field) -> Self {
                v.0
            }
        }

        impl rand::distributions::Distribution<$field> for rand::distributions::Standard {
            fn sample<R: crate::rand::Rng + ?Sized>(&self, rng: &mut R) -> $field {
                <$field>::from(rng.gen::<u128>())
            }
        }

        impl std::fmt::Debug for $field {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}_mod{}", self.0, Self::PRIME)
            }
        }

        #[cfg(test)]
        impl std::cmp::PartialEq<u128> for $field {
            fn eq(&self, other: &u128) -> bool {
                self.as_u128() == *other
            }
        }

        #[cfg(test)]
        impl std::cmp::PartialEq<$field> for u128 {
            fn eq(&self, other: &$field) -> bool {
                *self == other.as_u128()
            }
        }

        #[cfg(all(test, not(feature = "shuttle")))]
        mod common_tests {
            use super::*;
            use crate::bits::Serializable;
            use generic_array::GenericArray;
            use proptest::proptest;

            #[test]
            fn zero() {
                let prime = u128::from($field::PRIME);
                assert_eq!($field::ZERO, $field::from(prime), "from takes a modulus",);
                assert_eq!($field::ZERO, $field::ZERO + $field::ZERO);
                assert_eq!($field::ZERO, $field::ZERO - $field::ZERO);
                assert_eq!($field::from(prime - 1), $field::ZERO - $field::ONE);
                assert_eq!($field::ZERO, $field::ZERO * $field::ONE);
            }

            proptest! {

                #[test]
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

mod fp31 {
    use typenum::U1;
    field_impl! { Fp31, u8, 31, U1 }

    #[cfg(all(test, not(feature = "shuttle")))]
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
    use typenum::U4;
    field_impl! { Fp32BitPrime, u32, 4_294_967_291, U4 }

    #[cfg(all(test, not(feature = "shuttle")))]
    mod specialized_tests {
        use super::*;

        #[test]
        fn thirty_two_bit_prime() {
            let x = Fp32BitPrime::from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::from(4_294_967_289_u32); // PRIME - 2

            assert_eq!(x - y, Fp32BitPrime::ONE);
            assert_eq!(y - x, Fp32BitPrime::from(Fp32BitPrime::PRIME - 1));
            assert_eq!(y + x, Fp32BitPrime::from(Fp32BitPrime::PRIME - 3));

            assert_eq!(x * y, Fp32BitPrime::from(2_u32),);

            let x = Fp32BitPrime::from(3_192_725_551_u32);
            let y = Fp32BitPrime::from(1_471_265_983_u32);

            assert_eq!(x - y, Fp32BitPrime::from(1_721_459_568_u32));
            assert_eq!(y - x, Fp32BitPrime::from(2_573_507_723_u32));
            assert_eq!(x + y, Fp32BitPrime::from(369_024_243_u32));

            assert_eq!(x * y, Fp32BitPrime::from(513_684_208_u32),);
        }

        #[test]
        fn thirty_two_bit_additive_wrapping() {
            let x = Fp32BitPrime::from(u32::MAX - 20);
            let y = Fp32BitPrime::from(20_u32);
            assert_eq!(x + y, Fp32BitPrime::from(4_u32));

            let x = Fp32BitPrime::from(u32::MAX - 20);
            let y = Fp32BitPrime::from(21_u32);
            assert_eq!(x + y, Fp32BitPrime::from(5_u32));

            let x = Fp32BitPrime::from(u32::MAX - 20);
            let y = Fp32BitPrime::from(22_u32);
            assert_eq!(x + y, Fp32BitPrime::from(6_u32));

            let x = Fp32BitPrime::from(4_294_967_290_u32); // PRIME - 1
            let y = Fp32BitPrime::from(4_294_967_290_u32); // PRIME - 1
            assert_eq!(x + y, Fp32BitPrime::from(4_294_967_289_u32));
        }
    }
}

pub use fp31::Fp31;
pub use fp32bit::Fp32BitPrime;
