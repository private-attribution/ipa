use super::{field::BinaryField, Field};
use std::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Not};
// something weird is happening and compiler does not see the use of this macro inside field_impl
// but it happily complains if this import is removed.
#[allow(unused_imports)]
use paste::paste;

macro_rules! field_impl {
    ( $field:ty, $int:ty ) => {
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

        #[cfg(test)]
        paste! {
            #[cfg(test)]
            mod [< $field:lower _tests >] {
                use super::*;
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

                #[test]
                fn ser_not_enough_capacity() {
                    let mut buf = [0; 0];
                    assert!(matches!(
                        $field::ONE.serialize(&mut buf),
                        Err(e) if e.kind() == std::io::ErrorKind::WriteZero));
                }

                #[test]
                fn de_buf_too_small() {
                    let mut buf = [0; 0];
                    assert!(matches!(
                                    $field::deserialize(&mut buf),
                                    Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof));
                }

                #[test]
                fn can_write_into_buf_larger_than_required() {
                    let mut buf = vec![0_u8; $field::SIZE_IN_BYTES as usize + 1];

                    // panic will show the error while assert will just tell us that something went wrong
                    $field::ONE.serialize(&mut buf).unwrap();
                }

                proptest! {
                    #[test]
                    fn serde(v in 0..$field::PRIME) {
                        let field_v = $field(v);
                        let mut buf = vec![0; $field::SIZE_IN_BYTES as usize];
                        field_v.serialize(&mut buf).unwrap();

                        assert_eq!(field_v, $field::deserialize(&mut buf).unwrap());
                    }
                }
            }
        }
    };
}

#[derive(Clone, Copy, PartialEq)]
pub struct Fp2(<Self as Field>::Integer);

field_impl! { Fp2, u8 }

impl Field for Fp2 {
    type Integer = u8;
    const PRIME: Self::Integer = 2;
    const ZERO: Self = Fp2(0);
    const ONE: Self = Fp2(1);
}

impl BinaryField for Fp2 {}

impl BitAnd for Fp2 {
    type Output = Self;

    fn bitand(self, rhs: Self) -> Self::Output {
        Self(self.0 & rhs.0)
    }
}

impl BitAndAssign for Fp2 {
    fn bitand_assign(&mut self, rhs: Self) {
        *self = *self & rhs;
    }
}

impl BitOr for Fp2 {
    type Output = Self;

    fn bitor(self, rhs: Self) -> Self::Output {
        Self(self.0 | rhs.0)
    }
}

impl BitOrAssign for Fp2 {
    fn bitor_assign(&mut self, rhs: Self) {
        *self = *self | rhs;
    }
}

impl BitXor for Fp2 {
    type Output = Self;

    fn bitxor(self, rhs: Self) -> Self::Output {
        Self(self.0 ^ rhs.0)
    }
}

impl BitXorAssign for Fp2 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs;
    }
}

impl Not for Fp2 {
    type Output = Self;

    fn not(self) -> Self::Output {
        // Using `::from()` makes sure that the internal value is always 0 or 1, but since
        // we use `u8` to represent a binary value, `!0` and `!1` will result in 255 and
        // 254 respectively. Add `& 1` at the end to mask the LSB.
        Self(!self.0 & 1)
    }
}

#[derive(Clone, Copy, PartialEq)]
pub struct Fp31(<Self as Field>::Integer);

impl Field for Fp31 {
    type Integer = u8;
    const PRIME: Self::Integer = 31;
    const ZERO: Self = Fp31(0);
    const ONE: Self = Fp31(1);
}

field_impl! { Fp31, u8 }

#[derive(Clone, Copy, PartialEq)]
pub struct Fp32BitPrime(<Self as Field>::Integer);

impl Field for Fp32BitPrime {
    type Integer = u32;
    const PRIME: Self::Integer = 4_294_967_291; // 2^32 - 5
    const ZERO: Self = Fp32BitPrime(0);
    const ONE: Self = Fp32BitPrime(1);
}

field_impl! { Fp32BitPrime, u32 }

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use super::{Field, Fp2, Fp31, Fp32BitPrime};

    #[allow(clippy::eq_op)]
    #[test]
    fn fp2() {
        let x = Fp2::from(false);
        let y = Fp2::from(true);

        assert_eq!(Fp2(1), x + y);
        assert_eq!(Fp2(0), x * y);
        assert_eq!(Fp2(1), x - y);

        let mut x = Fp2(1);
        x += Fp2(1);
        assert_eq!(Fp2(0), x);
    }

    #[test]
    fn fp2_binary_op() {
        let zero = Fp2::ZERO;
        let one = Fp2::ONE;

        assert_eq!(one, one & one);
        assert_eq!(zero, zero & one);
        assert_eq!(zero, one & zero);
        assert_eq!(zero, zero & zero);
        assert_eq!(zero, Fp2::from(31_u128) & Fp2::from(32_u128));
        assert_eq!(one, Fp2::from(31_u128) & Fp2::from(63_u128));

        assert_eq!(zero, zero | zero);
        assert_eq!(one, one | one);
        assert_eq!(one, zero | one);
        assert_eq!(one, one | zero);
        assert_eq!(one, Fp2::from(31_u128) | Fp2::from(32_u128));
        assert_eq!(zero, Fp2::from(32_u128) | Fp2::from(64_u128));

        assert_eq!(zero, zero ^ zero);
        assert_eq!(one, zero ^ one);
        assert_eq!(one, one ^ zero);
        assert_eq!(zero, one ^ one);
        assert_eq!(one, Fp2::from(31_u128) ^ Fp2::from(32_u128));
        assert_eq!(zero, Fp2::from(32_u128) ^ Fp2::from(64_u128));

        assert_eq!(one, !zero);
        assert_eq!(zero, !one);
        assert_eq!(one, !Fp2::from(32_u128));
        assert_eq!(zero, !Fp2::from(31_u128));
    }

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
