use std::{
    fmt::Debug,
    ops::{Add, Mul, Neg, Sub},
};

use crate::field::Field;
use crate::prss::Participant;

pub enum HelperIdentity {
    H1,
    H2,
    H3,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplicatedSecretSharing<T>(T, T);

impl<T: Field> ReplicatedSecretSharing<T> {
    #[must_use]
    pub fn construct(a: T, b: T) -> Self {
        Self(a, b)
    }

    #[must_use]
    pub fn mult_step1(&self, rhs: Self, rng: &Participant, index: u128) -> (Self, T) {
        let (s0, s1) = rng.generate_fields(index);
        let d: T = (self.0 * rhs.1) + (self.1 * rhs.0) - s0;
        (
            Self::construct(self.0 * rhs.0 + s0, self.1 * rhs.1 + d + s1),
            d,
        )
    }

    #[must_use]
    pub fn mult_step2(incomplete_shares: Self, d_value_received: T) -> Self {
        Self::construct(incomplete_shares.0 + d_value_received, incomplete_shares.1)
    }

    #[must_use]
    pub fn xor_step1(&self, rhs: Self, rng: &Participant, index: u128) -> (Self, T) {
        self.mult_step1(rhs, rng, index)
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

    fn mul(self, rhs: T) -> Self {
        Self(rhs * self.0, rhs * self.1)
    }
}

pub struct RandomShareGenerationHelper {
    rng: Participant,
    identity: HelperIdentity,
}

impl RandomShareGenerationHelper {
    #[must_use]
    pub fn init(rng: Participant, identity: HelperIdentity) -> Self {
        Self { rng, identity }
    }

    #[must_use]
    pub fn gen_random_binary(&mut self) -> (bool, bool) {
        self.rng.next_bits()
    }

    #[must_use]
    pub fn split_binary<T: Field>(
        &self,
        left: bool,
        right: bool,
    ) -> (
        ReplicatedSecretSharing<T>,
        ReplicatedSecretSharing<T>,
        ReplicatedSecretSharing<T>,
    ) {
        let left = u128::from(left);
        let right = u128::from(right);
        match self.identity {
            HelperIdentity::H1 => (
                ReplicatedSecretSharing::construct(T::from(left), T::ZERO),
                ReplicatedSecretSharing::construct(T::ZERO, T::from(right)),
                ReplicatedSecretSharing::construct(T::ZERO, T::ZERO),
            ),
            HelperIdentity::H2 => (
                ReplicatedSecretSharing::construct(T::ZERO, T::ZERO),
                ReplicatedSecretSharing::construct(T::from(left), T::ZERO),
                ReplicatedSecretSharing::construct(T::ZERO, T::from(right)),
            ),
            HelperIdentity::H3 => (
                ReplicatedSecretSharing::construct(T::ZERO, T::from(right)),
                ReplicatedSecretSharing::construct(T::ZERO, T::ZERO),
                ReplicatedSecretSharing::construct(T::from(left), T::ZERO),
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::modulus_convert::{
        HelperIdentity, RandomShareGenerationHelper, ReplicatedSecretSharing,
    };

    use crate::field::Fp31;
    use crate::prss::{Participant, ParticipantSetup};
    use rand::thread_rng;

    fn make_three() -> (
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
        RandomShareGenerationHelper,
    ) {
        let mut r = thread_rng();
        let setup1 = ParticipantSetup::new(&mut r);
        let setup2 = ParticipantSetup::new(&mut r);
        let setup3 = ParticipantSetup::new(&mut r);
        let (pk1_l, pk1_r) = setup1.public_keys();
        let (pk2_l, pk2_r) = setup2.public_keys();
        let (pk3_l, pk3_r) = setup3.public_keys();

        let p1 = setup1.setup(&pk3_r, &pk2_l);
        let p2 = setup2.setup(&pk1_r, &pk3_l);
        let p3 = setup3.setup(&pk2_r, &pk1_l);

        // Helper 1
        let h1 = RandomShareGenerationHelper::init(p1, HelperIdentity::H1);

        // Helper 2
        let h2 = RandomShareGenerationHelper::init(p2, HelperIdentity::H2);

        // Helper 3
        let h3 = RandomShareGenerationHelper::init(p3, HelperIdentity::H3);

        (h1, h2, h3)
    }

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
            ReplicatedSecretSharing::construct(Fp31::from(a), Fp31::from(b)),
            ReplicatedSecretSharing::construct(Fp31::from(b), Fp31::from(c)),
            ReplicatedSecretSharing::construct(Fp31::from(c), Fp31::from(a)),
        )
    }

    // Yeah, yeah... too many arguments... but it's just a test
    #[allow(clippy::too_many_arguments)]
    fn multiply_secret_shares(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a1: ReplicatedSecretSharing<Fp31>,
        a2: ReplicatedSecretSharing<Fp31>,
        a3: ReplicatedSecretSharing<Fp31>,
        b1: ReplicatedSecretSharing<Fp31>,
        b2: ReplicatedSecretSharing<Fp31>,
        b3: ReplicatedSecretSharing<Fp31>,
    ) -> (
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
    ) {
        let (h1_res, d1) = a1.mult_step1(b1, &h1.rng, 1);
        let (h2_res, d2) = a2.mult_step1(b2, &h2.rng, 1);
        let (h3_res, d3) = a3.mult_step1(b3, &h3.rng, 1);

        (
            ReplicatedSecretSharing::mult_step2(h1_res, d3),
            ReplicatedSecretSharing::mult_step2(h2_res, d1),
            ReplicatedSecretSharing::mult_step2(h3_res, d2),
        )
    }

    // Yeah, yeah... too many arguments... but it's just a test
    #[allow(clippy::too_many_arguments)]
    fn xor_secret_shares(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a1: ReplicatedSecretSharing<Fp31>,
        a2: ReplicatedSecretSharing<Fp31>,
        a3: ReplicatedSecretSharing<Fp31>,
        b1: ReplicatedSecretSharing<Fp31>,
        b2: ReplicatedSecretSharing<Fp31>,
        b3: ReplicatedSecretSharing<Fp31>,
    ) -> (
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
    ) {
        let (h1_res, d1) = a1.xor_step1(b1, &h1.rng, 1);
        let (h2_res, d2) = a2.xor_step1(b2, &h2.rng, 1);
        let (h3_res, d3) = a3.xor_step1(b3, &h3.rng, 1);

        (
            a1.xor_step2(b1, h1_res, d3),
            a2.xor_step2(b2, h2_res, d1),
            a3.xor_step2(b3, h3_res, d2),
        )
    }

    fn assert_valid_secret_sharing(
        res1: ReplicatedSecretSharing<Fp31>,
        res2: ReplicatedSecretSharing<Fp31>,
        res3: ReplicatedSecretSharing<Fp31>,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: ReplicatedSecretSharing<Fp31>,
        a2: ReplicatedSecretSharing<Fp31>,
        a3: ReplicatedSecretSharing<Fp31>,
        expected_value: u128,
    ) {
        assert_eq!(a1.0 + a2.0 + a3.0, Fp31::from(expected_value));
        assert_eq!(a1.1 + a2.1 + a3.1, Fp31::from(expected_value));
    }

    fn mult_test_case(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a: (u8, u8, u8),
        b: (u8, u8, u8),
        expected_output: u8,
    ) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 * r2
        let (res1, res2, res3) = self::multiply_secret_shares(h1, h2, h3, a1, a2, a3, b1, b2, b3);

        assert_eq!(res1.0 + res2.0 + res3.0, Fp31::from(expected_output));
        assert_eq!(res1.1 + res2.1 + res3.1, Fp31::from(expected_output));

        assert_valid_secret_sharing(res1, res2, res3);
    }

    #[test]
    fn test_simple_multiplication() {
        let (h1, h2, h3) = self::make_three();

        mult_test_case(&h1, &h2, &h3, (1, 0, 0), (0, 1, 0), 1);

        mult_test_case(&h1, &h2, &h3, (1, 0, 0), (0, 0, 1), 1);

        mult_test_case(&h1, &h2, &h3, (0, 1, 0), (0, 0, 1), 1);

        mult_test_case(&h1, &h2, &h3, (0, 0, 0), (0, 0, 1), 0);

        mult_test_case(&h1, &h2, &h3, (1, 30, 0), (0, 0, 1), 0);

        mult_test_case(&h1, &h2, &h3, (1, 30, 1), (0, 0, 1), 1);

        mult_test_case(&h1, &h2, &h3, (1, 0, 30), (0, 30, 1), 0);
    }

    fn xor_test_case(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a: (u8, u8, u8),
        b: (u8, u8, u8),
        expected_output: u8,
    ) {
        let (a1, a2, a3) = secret_share(a.0, a.1, a.2);
        let (b1, b2, b3) = secret_share(b.0, b.1, b.2);

        // Compute r1 ^ r2
        let (res1, res2, res3) = self::xor_secret_shares(h1, h2, h3, a1, a2, a3, b1, b2, b3);

        assert_eq!(res1.0 + res2.0 + res3.0, Fp31::from(expected_output));
        assert_eq!(res1.1 + res2.1 + res3.1, Fp31::from(expected_output));

        assert_valid_secret_sharing(res1, res2, res3);
    }

    #[test]
    fn test_simple_xor() {
        let (h1, h2, h3) = self::make_three();

        xor_test_case(&h1, &h2, &h3, (1, 0, 0), (0, 0, 1), 0);
        xor_test_case(&h1, &h2, &h3, (1, 0, 0), (0, 1, 0), 0);
        xor_test_case(&h1, &h2, &h3, (0, 1, 0), (0, 0, 1), 0);

        xor_test_case(&h1, &h2, &h3, (1, 0, 0), (1, 0, 0), 0);
        xor_test_case(&h1, &h2, &h3, (0, 1, 0), (0, 1, 0), 0);
        xor_test_case(&h1, &h2, &h3, (0, 0, 1), (0, 0, 1), 0);

        xor_test_case(&h1, &h2, &h3, (0, 0, 0), (1, 0, 0), 1);
        xor_test_case(&h1, &h2, &h3, (0, 0, 0), (0, 1, 0), 1);
        xor_test_case(&h1, &h2, &h3, (0, 0, 0), (0, 0, 1), 1);

        xor_test_case(&h1, &h2, &h3, (1, 0, 0), (0, 0, 0), 1);
        xor_test_case(&h1, &h2, &h3, (0, 1, 0), (0, 0, 0), 1);
        xor_test_case(&h1, &h2, &h3, (0, 0, 1), (0, 0, 0), 1);

        xor_test_case(&h1, &h2, &h3, (1, 30, 0), (0, 0, 1), 1);
        xor_test_case(&h1, &h2, &h3, (1, 30, 1), (0, 0, 1), 0);
        xor_test_case(&h1, &h2, &h3, (1, 0, 30), (0, 30, 1), 0);
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

    fn xor(
        a: (
            ReplicatedSecretSharing<Fp31>,
            ReplicatedSecretSharing<Fp31>,
            ReplicatedSecretSharing<Fp31>,
        ),
        b: (
            ReplicatedSecretSharing<Fp31>,
            ReplicatedSecretSharing<Fp31>,
            ReplicatedSecretSharing<Fp31>,
        ),
        rng1: &Participant,
        rng2: &Participant,
        rng3: &Participant,
        idx: u128,
    ) -> (
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
        ReplicatedSecretSharing<Fp31>,
    ) {
        let (c1, d1) = a.0.xor_step1(b.0, rng1, idx);
        let (c2, d2) = a.1.xor_step1(b.1, rng2, idx);
        let (c3, d3) = a.2.xor_step1(b.2, rng3, idx);

        (
            a.0.xor_step2(b.0, c1, d3),
            a.1.xor_step2(b.1, c2, d1),
            a.2.xor_step2(b.2, c3, d2),
        )
    }

    #[test]
    fn test_three_helpers() {
        let (mut h1, mut h2, mut h3) = self::make_three();

        for index in 0..100 {
            let (r1, _r2) = h1.gen_random_binary();
            let (r2, _r3) = h2.gen_random_binary();
            let (r3, _r1) = h3.gen_random_binary();

            let h1_split = h1.split_binary(r1, r2);
            let h2_split = h2.split_binary(r2, r3);
            let h3_split = h3.split_binary(r3, r1);

            // validate r1
            assert_valid_secret_sharing(h1_split.0, h2_split.0, h3_split.0);
            assert_secret_shared_value(h1_split.0, h2_split.0, h3_split.0, u128::from(r1));

            // validate r2
            assert_valid_secret_sharing(h1_split.1, h2_split.1, h3_split.1);
            assert_secret_shared_value(h1_split.1, h2_split.1, h3_split.1, u128::from(r2));

            // validate r3
            assert_valid_secret_sharing(h1_split.2, h2_split.2, h3_split.2);
            assert_secret_shared_value(h1_split.2, h2_split.2, h3_split.2, u128::from(r3));

            // Compute r1 ^ r2
            let r1_xor_r2 = xor(
                (h1_split.0, h2_split.0, h3_split.0),
                (h1_split.1, h2_split.1, h3_split.1),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index,
            );

            // validate r1 ^ r2
            assert_valid_secret_sharing(r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2);
            assert_secret_shared_value(r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2, u128::from(r1 ^ r2));

            // Compute (r1 ^ r2) ^ r3
            let r1_xor_r2_xor_r3 = xor(
                (r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2),
                (h1_split.2, h2_split.2, h3_split.2),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index + 1,
            );

            // validate (r1 ^ r2) ^ r3
            assert_valid_secret_sharing(r1_xor_r2_xor_r3.0, r1_xor_r2_xor_r3.1, r1_xor_r2_xor_r3.2);
            assert_secret_shared_value(
                r1_xor_r2_xor_r3.0,
                r1_xor_r2_xor_r3.1,
                r1_xor_r2_xor_r3.2,
                u128::from(r1 ^ r2 ^ r3),
            );
        }
    }
}
