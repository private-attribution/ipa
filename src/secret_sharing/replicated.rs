use super::Field;
use super::Share;
use crate::helpers::Identity;
use std::fmt::Formatter;
use std::ops::AddAssign;
use std::ops::SubAssign;
use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Replicated<T>(T, T);

impl<T: Debug> Debug for Replicated<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "({:?}, {:?})", self.0, self.1)
    }
}

impl<S: Share> Default for Replicated<S> {
    fn default() -> Self {
        Replicated::new(S::DEFAULT, S::DEFAULT)
    }
}

impl<S: Share> Replicated<S> {
    #[must_use]
    pub fn new(a: S, b: S) -> Self {
        Self(a, b)
    }

    pub fn as_tuple(&self) -> (S, S) {
        (self.0, self.1)
    }
}

impl<F: Field> Replicated<F> {
    /// Returns share of value one.
    #[must_use]
    pub fn one(helper_identity: Identity) -> Self {
        match helper_identity {
            Identity::H1 => Self::new(F::ONE, F::ZERO),
            Identity::H2 => Self::new(F::ZERO, F::ZERO),
            Identity::H3 => Self::new(F::ZERO, F::ONE),
        }
    }
}

impl<F: Field> Add for Replicated<F> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<F: Field> AddAssign for Replicated<F> {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl<F: Field> SubAssign for Replicated<F> {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl<F: Field> Neg for Replicated<F> {
    type Output = Self;

    fn neg(self) -> Self {
        Self(-self.0, -self.1)
    }
}

impl<F: Field> Sub for Replicated<F> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<F: Field> Mul<F> for Replicated<F> {
    type Output = Self;

    fn mul(self, rhs: F) -> Self {
        Self(rhs * self.0, rhs * self.1)
    }
}

#[cfg(test)]
mod tests {
    use super::Replicated;
    use crate::secret_sharing::Fp31;

    fn secret_share(a: u8, b: u8, c: u8) -> (Replicated<Fp31>, Replicated<Fp31>, Replicated<Fp31>) {
        (
            Replicated::new(Fp31::from(a), Fp31::from(b)),
            Replicated::new(Fp31::from(b), Fp31::from(c)),
            Replicated::new(Fp31::from(c), Fp31::from(a)),
        )
    }

    fn assert_valid_secret_sharing(
        res1: Replicated<Fp31>,
        res2: Replicated<Fp31>,
        res3: Replicated<Fp31>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: Replicated<Fp31>,
        a2: Replicated<Fp31>,
        a3: Replicated<Fp31>,
        expected_value: u128,
    ) {
        assert_eq!(a1.0 + a2.0 + a3.0, Fp31::from(expected_value));
        assert_eq!(a1.1 + a2.1 + a3.1, Fp31::from(expected_value));
    }

    fn addition_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 + r2
        let res1 = a1 + b1;
        let res2 = a2 + b2;
        let res3 = a3 + b3;

        assert_valid_secret_sharing(res1, res2, res3);
        assert_secret_shared_value(res1, res2, res3, expected_output);
    }

    #[test]
    fn test_simple_addition() {
        addition_test_case((1, 0, 0), (1, 0, 0), 2);
        addition_test_case((1, 0, 0), (0, 1, 0), 2);
        addition_test_case((1, 0, 0), (0, 0, 1), 2);

        addition_test_case((0, 1, 0), (1, 0, 0), 2);
        addition_test_case((0, 1, 0), (0, 1, 0), 2);
        addition_test_case((0, 1, 0), (0, 0, 1), 2);

        addition_test_case((0, 0, 1), (1, 0, 0), 2);
        addition_test_case((0, 0, 1), (0, 1, 0), 2);
        addition_test_case((0, 0, 1), (0, 0, 1), 2);

        addition_test_case((0, 0, 0), (1, 0, 0), 1);
        addition_test_case((0, 0, 0), (0, 1, 0), 1);
        addition_test_case((0, 0, 0), (0, 0, 1), 1);

        addition_test_case((1, 0, 0), (0, 0, 0), 1);
        addition_test_case((0, 1, 0), (0, 0, 0), 1);
        addition_test_case((0, 0, 1), (0, 0, 0), 1);

        addition_test_case((0, 0, 0), (0, 0, 0), 0);

        addition_test_case((1, 3, 5), (10, 0, 2), 21);
    }

    fn subtraction_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 - r2
        let res1 = a1 - b1;
        let res2 = a2 - b2;
        let res3 = a3 - b3;

        assert_valid_secret_sharing(res1, res2, res3);
        assert_secret_shared_value(res1, res2, res3, expected_output);
    }

    #[test]
    fn test_simple_subtraction() {
        subtraction_test_case((1, 0, 0), (1, 0, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 1, 0), 0);
        subtraction_test_case((1, 0, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 1, 0), (1, 0, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 1, 0), 0);
        subtraction_test_case((0, 1, 0), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 1), (1, 0, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 1, 0), 0);
        subtraction_test_case((0, 0, 1), (0, 0, 1), 0);

        subtraction_test_case((0, 0, 0), (1, 0, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 1, 0), 30);
        subtraction_test_case((0, 0, 0), (0, 0, 1), 30);

        subtraction_test_case((1, 0, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 1, 0), (0, 0, 0), 1);
        subtraction_test_case((0, 0, 1), (0, 0, 0), 1);

        subtraction_test_case((0, 0, 0), (0, 0, 0), 0);

        subtraction_test_case((1, 3, 5), (10, 0, 2), 28);
    }

    fn mult_by_constant_test_case(a: (u8, u8, u8), c: u8, expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);

        let res1 = a1 * Fp31::from(c);
        let res2 = a2 * Fp31::from(c);
        let res3 = a3 * Fp31::from(c);

        assert_valid_secret_sharing(res1, res2, res3);
        assert_secret_shared_value(res1, res2, res3, expected_output);
    }

    #[test]
    fn test_mult_by_constant() {
        mult_by_constant_test_case((1, 0, 0), 2, 2);
        mult_by_constant_test_case((0, 1, 0), 2, 2);
        mult_by_constant_test_case((0, 0, 1), 2, 2);
        mult_by_constant_test_case((0, 0, 0), 2, 0);
    }
}
