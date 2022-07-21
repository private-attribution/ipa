use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use crate::field::Field;
use crate::prss::Participant;

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplicatedSecretSharing<T>(T, T);

impl<T: Field> ReplicatedSecretSharing<T> {
    #[must_use]
    pub fn new(a: T, b: T) -> Self {
        Self(a, b)
    }

    /// Assert that the secret value is equal to a specific value
    /// # Panics
    /// If the secret sharing is invalid
    pub fn assert_valid_secret_sharing(
        res1: ReplicatedSecretSharing<T>,
        res2: ReplicatedSecretSharing<T>,
        res3: ReplicatedSecretSharing<T>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    ///
    /// # Panics
    /// If the secret shared value does not match the expected value
    pub fn assert_secret_shared_value(
        a1: ReplicatedSecretSharing<T>,
        a2: ReplicatedSecretSharing<T>,
        a3: ReplicatedSecretSharing<T>,
        expected_value: u128,
    ) {
        assert_eq!(a1.0 + a2.0 + a3.0, T::from(expected_value));
        assert_eq!(a1.1 + a2.1 + a3.1, T::from(expected_value));
    }

    #[must_use]
    pub fn mult_step1(
        &self,
        rhs: Self,
        rng: &Participant,
        index: u128,
        send_d: bool,
        right_sent_d: bool,
    ) -> (Self, T) {
        let (s0, s1) = rng.generate_fields(index);

        let mut d = T::ZERO;
        let mut left_share = self.0 * rhs.0;
        let mut right_share = self.1 * rhs.1;
        if send_d {
            d = (self.0 * rhs.1) + (self.1 * rhs.0) - s0;
            left_share += s0;
            right_share += d;
        }
        if right_sent_d {
            right_share += s1;
        }
        (Self::new(left_share, right_share), d)
    }

    #[must_use]
    pub fn mult_step2(incomplete_shares: Self, d_value_received: T) -> Self {
        Self::new(incomplete_shares.0 + d_value_received, incomplete_shares.1)
    }

    #[must_use]
    pub fn xor_step1(&self, rhs: Self, rng: &Participant, index: u128) -> (Self, T) {
        self.mult_step1(rhs, rng, index, true, true)
    }

    #[must_use]
    pub fn xor_step2(&self, rhs: Self, incomplete_share: Self, d_value_received: T) -> Self {
        *self + rhs - Self::mult_step2(incomplete_share, d_value_received) * T::from(2)
    }
}

impl<T: Field> Add for ReplicatedSecretSharing<T> {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl<T: Field> Neg for ReplicatedSecretSharing<T> {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl<T: Field> Sub for ReplicatedSecretSharing<T> {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl<T: Field> Mul<T> for ReplicatedSecretSharing<T> {
    type Output = Self;

    fn mul(self, rhs: T) -> Self::Output {
        Self(rhs * self.0, rhs * self.1)
    }
}

#[cfg(test)]
mod tests {
    use crate::replicated_secret_sharing::ReplicatedSecretSharing;

    use crate::field::Fp31;

    fn secret_share(
        a: u8,
        b: u8,
        c: u8,
    ) -> (
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
    ) {
        (
            ReplicatedSecretSharing::new(Fp31::from(a), Fp31::from(b)),
            ReplicatedSecretSharing::new(Fp31::from(b), Fp31::from(c)),
            ReplicatedSecretSharing::new(Fp31::from(c), Fp31::from(a)),
        )
    }

    fn addition_test_case(a: (u8, u8, u8), b: (u8, u8, u8), expected_output: u128) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 + r2
        let res1 = a1 + b1;
        let res2 = a2 + b2;
        let res3 = a3 + b3;

        ReplicatedSecretSharing::assert_valid_secret_sharing(res1, res2, res3);
        ReplicatedSecretSharing::assert_secret_shared_value(res1, res2, res3, expected_output);
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

        ReplicatedSecretSharing::assert_valid_secret_sharing(res1, res2, res3);
        ReplicatedSecretSharing::assert_secret_shared_value(res1, res2, res3, expected_output);
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

        ReplicatedSecretSharing::assert_valid_secret_sharing(res1, res2, res3);
        ReplicatedSecretSharing::assert_secret_shared_value(res1, res2, res3, expected_output);
    }

    #[test]
    fn test_mult_by_constant() {
        mult_by_constant_test_case((1, 0, 0), 2, 2);
        mult_by_constant_test_case((0, 1, 0), 2, 2);
        mult_by_constant_test_case((0, 0, 1), 2, 2);
        mult_by_constant_test_case((0, 0, 0), 2, 0);
    }
}
