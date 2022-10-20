use std::ops::{BitAnd, Shr};
use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

// Trait for primitive integer types used to represent the underlying type for field values
pub trait Int:
    Sized
    + Copy
    + Debug
    + Ord
    + Sub<Output = Self>
    + Into<u128>
    + From<u8>
    + Shr<u32, Output = Self>
    + BitAnd<Self, Output = Self>
    + PartialEq
{
    const BITS: u32;
}

impl Int for u8 {
    const BITS: u32 = u8::BITS;
}

pub trait Field:
    Add<Output = Self>
    + AddAssign
    + Neg<Output = Self>
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + From<u128>
    + Into<Self::Integer>
    + Clone
    + Copy
    + PartialEq
    + Debug
    + Send
    + Sized
    + Serialize
    + DeserializeOwned
    + 'static
{
    type Integer: Int;

    const PRIME: Self::Integer;
    /// Additive identity element
    const ZERO: Self;
    /// Multiplicative identity element
    const ONE: Self;

    /// computes the multiplicative inverse of `self`. It is UB if `self` is 0.
    #[must_use]
    fn invert(&self) -> Self {
        debug_assert!(
            self != &Self::ZERO,
            "Multiplicative inverse is not defined for 0"
        );

        self.pow(Self::PRIME - Self::ONE.into() - Self::ONE.into())
    }

    /// Computes modular exponentiation, self^exp (mod PRIME)
    #[must_use]
    fn pow(&self, exp: Self::Integer) -> Self {
        let mut term = Self::ONE;
        // compute: x^exp
        // binary representation of exp: a_k*2^k + a_k-1*2^k-1 + ... + a_0*2^0
        // x^exp = x^a_0 + (x^2)^a_1 + ... + (x^(2^k))^a_k
        // * start at 0 and each time square the term.
        // * term contributes to the result iff a_k bit is 1 (as (x^a)^0 == 1)
        for i in (0..Self::Integer::BITS).rev() {
            term *= term;
            if (exp >> i) & Self::Integer::from(1) != Self::Integer::from(0) {
                term *= *self;
            }
        }

        term
    }

    /// Blanket implementation to represent the instance of this trait as 16 byte integer.
    /// Uses the fact that such conversion already exists via `Self` -> `Self::Integer` -> `Into<u128>`
    fn as_u128(&self) -> u128 {
        let int: Self::Integer = (*self).into();
        int.into()
    }
}

// TODO(mt) - this code defining fields can be turned into a macro if we ever
// need lots of fields with different primes.

#[derive(Clone, Copy, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct Fp31(<Self as Field>::Integer);

impl From<Fp31> for u8 {
    fn from(v: Fp31) -> Self {
        v.0
    }
}

impl Field for Fp31 {
    type Integer = u8;
    const PRIME: Self::Integer = 31;
    const ZERO: Self = Fp31(0);
    const ONE: Self = Fp31(1);
}

impl Add for Fp31 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // TODO(mt) - constant time?
        Self((self.0 + rhs.0) % Self::PRIME)
    }
}

impl AddAssign for Fp31 {
    #[allow(clippy::assign_op_pattern)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Neg for Fp31 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self((Self::PRIME - self.0) % Self::PRIME)
    }
}

impl Sub for Fp31 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // TODO(mt) - constant time?
        // Note: no upcast needed here because `2*p < u8::MAX`.
        Self((Self::PRIME + self.0 - rhs.0) % Self::PRIME)
    }
}

impl SubAssign for Fp31 {
    #[allow(clippy::assign_op_pattern)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl Mul for Fp31 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        // TODO(mt) - constant time?
        let c = u16::from;
        #[allow(clippy::cast_possible_truncation)]
        Self(((c(self.0) * c(rhs.0)) % c(Self::PRIME)) as <Self as Field>::Integer)
    }
}

impl MulAssign for Fp31 {
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
impl<T: Into<u128>> From<T> for Fp31 {
    fn from(v: T) -> Self {
        #[allow(clippy::cast_possible_truncation)]
        Self((v.into() % u128::from(Self::PRIME)) as <Self as Field>::Integer)
    }
}

impl Debug for Fp31 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_mod{}", self.0, Self::PRIME)
    }
}

#[cfg(test)]
mod test {
    use super::{Field, Fp31};
    use std::ops::Mul;

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
        assert_eq!(
            Fp31(0),
            Fp31::from(<Fp31 as Field>::PRIME),
            "from takes a modulus"
        );
        assert_eq!(Fp31(0), Fp31(0) + Fp31(0));
        assert_eq!(Fp31(0), Fp31(0) + Fp31(0));
        assert_eq!(Fp31(<Fp31 as Field>::PRIME - 1), Fp31(0) - Fp31(1));
        assert_eq!(Fp31(0), Fp31(0) * Fp31(1));
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
        for i in 1..Fp31::PRIME {
            let field_element = Fp31(i);
            assert_eq!(
                Fp31::ONE,
                field_element.invert().mul(field_element),
                "{field_element:?}*1/{field_element:?} != 1"
            );
        }
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
