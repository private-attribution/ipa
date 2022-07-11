use std::{
    fmt::Debug,
    ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

pub trait Field:
    Add<Output = Self>
    + AddAssign
    + Neg<Output = Self>
    + Sub<Output = Self>
    + SubAssign
    + Mul<Output = Self>
    + MulAssign
    + From<u128>
    + Clone
    + Copy
    + PartialEq
    + Debug
    + Sized
{
    type Integer;
    const PRIME: Self::Integer;
}

// TODO(mt) - this code defining fields can be turned into a macro if we ever
// need lots of fields with different primes.

#[derive(Clone, Copy, PartialEq)]
pub struct Fp31(<Self as Field>::Integer);

impl Field for Fp31 {
    type Integer = u8;
    const PRIME: Self::Integer = 31;
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
        Self(Self::PRIME - self.0)
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
    use super::Fp31;

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
