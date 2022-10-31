use super::{field::BinaryField, Field};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Debug,
    ops::{
        Add, AddAssign, BitAnd, BitAndAssign, BitOr, BitOrAssign, BitXor, BitXorAssign, Mul,
        MulAssign, Neg, Not, Sub, SubAssign,
    },
};

macro_rules! field_impl {
    ( $( $field:ty ),* ) => { $(
        impl Add for $field {
            type Output = Self;

            fn add(self, rhs: Self) -> Self::Output {
                Self((self.0 + rhs.0) % Self::PRIME)
            }
        }

        impl AddAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn add_assign(&mut self, rhs: Self) {
                *self = *self + rhs;
            }
        }

        impl Neg for $field {
            type Output = Self;

            fn neg(self) -> Self::Output {
                Self((Self::PRIME - self.0) % Self::PRIME)
            }
        }

        impl Sub for $field {
            type Output = Self;

            fn sub(self, rhs: Self) -> Self::Output {
                // TODO(mt) - constant time?
                let c = u128::from;
                Self(
                    ((c(Self::PRIME) + c(self.0) - c(rhs.0)) % c(Self::PRIME))
                        as <Self as Field>::Integer,
                )
            }
        }

        impl SubAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn sub_assign(&mut self, rhs: Self) {
                *self = *self - rhs;
            }
        }

        impl Mul for $field {
            type Output = Self;

            fn mul(self, rhs: Self) -> Self::Output {
                // TODO(mt) - constant time?
                let c = u128::from;
                #[allow(clippy::cast_possible_truncation)]
                Self(((c(self.0) * c(rhs.0)) % c(Self::PRIME)) as <Self as Field>::Integer)
            }
        }

        impl MulAssign for $field {
            #[allow(clippy::assign_op_pattern)]
            fn mul_assign(&mut self, rhs: Self) {
                *self = *self * rhs;
            }
        }

        impl From<$field> for u8 {
            fn from(v: $field) -> Self {
                v.0
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

        impl Debug for $field {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}_mod{}", self.0, Self::PRIME)
            }
        }
    )* };
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Fp2(<Self as Field>::Integer);

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
        Self((self.0 & rhs.0) & 1)
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
        Self((self.0 | rhs.0) & 1)
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
        Self((self.0 ^ rhs.0) & 1)
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
        Self((self.0 + 1) & 1)
    }
}

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Fp31(<Self as Field>::Integer);

impl Field for Fp31 {
    type Integer = u8;
    const PRIME: Self::Integer = 31;
    const ZERO: Self = Fp31(0);
    const ONE: Self = Fp31(1);
}

field_impl! { Fp2, Fp31 }

#[cfg(test)]
mod test {
    use super::{Field, Fp2, Fp31};
    use std::ops::Mul;

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
        assert_eq!(zero, Fp2(31) & Fp2(32));
        assert_eq!(one, Fp2(31) & Fp2(63));

        assert_eq!(zero, zero | zero);
        assert_eq!(one, one | one);
        assert_eq!(one, zero | one);
        assert_eq!(one, one | zero);
        assert_eq!(one, Fp2(31) | Fp2(32));
        assert_eq!(zero, Fp2(32) | Fp2(64));

        assert_eq!(zero, zero ^ zero);
        assert_eq!(one, zero ^ one);
        assert_eq!(one, one ^ zero);
        assert_eq!(zero, one ^ one);
        assert_eq!(one, Fp2(31) ^ Fp2(32));
        assert_eq!(zero, Fp2(32) ^ Fp2(64));

        assert_eq!(one, !zero);
        assert_eq!(zero, !one);
        assert_eq!(one, !Fp2(32));
        assert_eq!(zero, !Fp2(31));
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
    fn zero() {
        macro_rules! gen_zero_test {
            ( $( $field:ident ),* ) => { $(
                assert_eq!(
                    $field(0),
                    $field::from(<$field as Field>::PRIME),
                    "from takes a modulus",
                );
                assert_eq!($field(0), $field(0) + $field(0));
                assert_eq!($field(0), $field(0) - $field(0));
                assert_eq!($field(<$field as Field>::PRIME - 1), $field(0) - $field(1));
                assert_eq!($field(0), $field(0) * $field(1));
            ) * };
        }

        gen_zero_test!(Fp2, Fp31);
    }

    #[test]
    fn pow() {
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;

        assert_eq!(Fp31(2), Fp31(2).pow(1));
        assert_eq!(one, Fp31(2).pow(0));
        assert_eq!(one, one.pow(0));
        assert_eq!(one, one.pow(2));
        assert_eq!(zero, zero.pow(2));

        assert_eq!(Fp31(Fp31::PRIME - 1), Fp31(Fp31::PRIME - 1).pow(1));
        assert_eq!(one, Fp31(2).pow(Fp31::PRIME - 1));

        assert_eq!(Fp31(8), Fp31(2).pow(3));
        assert_eq!(Fp31(5), Fp31(6).pow(2));
        assert_eq!(Fp31(16), Fp31(4).pow(2));
        assert_eq!(Fp31(27), Fp31(3).pow(3));
    }

    #[test]
    fn invert() {
        macro_rules! gen_invert_test {
            ( $( $field:ident ),* ) => { $(
                for i in 1..$field::PRIME {
                    let field_element = $field(i);
                    assert_eq!(
                        $field::ONE,
                        field_element.invert().mul(field_element),
                        "{field_element:?}*1/{field_element:?} != 1"
                    );
                }
            ) * }
        }

        gen_invert_test!(Fp2, Fp31);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic]
    fn invert_panics_if_called_on_zero() {
        // assertion does not matter here, test should panic when `invert` is called.
        // it is here to silence #must_use warning
        assert_ne!(Fp31::ZERO, Fp31(0).invert());
    }
}
