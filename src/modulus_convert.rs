use std::{
    fmt::Debug,
    ops::{Add, Neg, Sub},
};

use crate::field::{Fp2, Fp31};
use crate::prss::Participant;
use bit_vec::BitVec;

pub enum HelperIdentity {
    H1,
    H2,
    H3,
}

pub struct RandomShareGenerationHelper {
    pub rng: Participant,
    identity: HelperIdentity,
}

pub struct IntermediateState1 {
    r_binary: ReplicatedBinarySecretSharing,
    r_shares: (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ),
    r1_x_r2: ReplicatedFp31SecretSharing,
}

pub struct IntermediateState2 {
    r_binary: ReplicatedBinarySecretSharing,
    r1_xor_r2: ReplicatedFp31SecretSharing,
    r3: ReplicatedFp31SecretSharing,
    r1_xor_r2_x_r3: ReplicatedFp31SecretSharing,
}

pub trait ReplicatedSecretSharing:
    Add<Output = Self>
    + Neg<Output = Self>
    + Sub<Output = Self>
    + Copy
    + Clone
    + PartialEq
    + Debug
    + Sized
{
    type Ring;
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplicatedBinarySecretSharing(
    <Self as ReplicatedSecretSharing>::Ring,
    <Self as ReplicatedSecretSharing>::Ring,
);

impl ReplicatedSecretSharing for ReplicatedBinarySecretSharing {
    type Ring = Fp2;
}

impl ReplicatedBinarySecretSharing {
    #[must_use]
    pub fn construct(a: Fp2, b: Fp2) -> ReplicatedBinarySecretSharing {
        ReplicatedBinarySecretSharing(a, b)
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ReplicatedFp31SecretSharing(
    pub <Self as ReplicatedSecretSharing>::Ring,
    pub <Self as ReplicatedSecretSharing>::Ring,
);

impl ReplicatedSecretSharing for ReplicatedFp31SecretSharing {
    type Ring = Fp31;
}

impl ReplicatedFp31SecretSharing {
    #[must_use]
    pub fn construct(a: Fp31, b: Fp31) -> Self {
        Self(a, b)
    }

    #[must_use]
    pub fn times(&self, c: Fp31) -> Self {
        Self(c * self.0, c * self.1)
    }

    #[must_use]
    pub fn mult_step1(
        &self,
        rhs: ReplicatedFp31SecretSharing,
        rng: &Participant,
        index: u128,
        send_d: bool,
        right_sent_d: bool,
    ) -> (ReplicatedFp31SecretSharing, Fp31) {
        let (s0, s1) = rng.generate_fields(index);

        let mut d = Fp31::from(0_u8);
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
        (Self::construct(left_share, right_share), d)
    }

    #[must_use]
    pub fn mult_step2(
        incomplete_shares: ReplicatedFp31SecretSharing,
        d_value_received: Fp31,
    ) -> ReplicatedFp31SecretSharing {
        Self::construct(incomplete_shares.0 + d_value_received, incomplete_shares.1)
    }

    #[must_use]
    pub fn xor_step1(
        &self,
        rhs: ReplicatedFp31SecretSharing,
        rng: &Participant,
        index: u128,
    ) -> (ReplicatedFp31SecretSharing, Fp31) {
        self.mult_step1(rhs, rng, index, true, true)
    }

    #[must_use]
    pub fn xor_step2(
        &self,
        rhs: ReplicatedFp31SecretSharing,
        incomplete_share: ReplicatedFp31SecretSharing,
        d_value_received: Fp31,
    ) -> ReplicatedFp31SecretSharing {
        *self + rhs - Self::mult_step2(incomplete_share, d_value_received).times(Fp31::from(2_u8))
    }
}

impl Add for ReplicatedFp31SecretSharing {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Neg for ReplicatedFp31SecretSharing {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Sub for ReplicatedFp31SecretSharing {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl Add for ReplicatedBinarySecretSharing {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0 + rhs.0, self.1 + rhs.1)
    }
}

impl Neg for ReplicatedBinarySecretSharing {
    type Output = Self;

    fn neg(self) -> Self::Output {
        Self(-self.0, -self.1)
    }
}

impl Sub for ReplicatedBinarySecretSharing {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self(self.0 - rhs.0, self.1 - rhs.1)
    }
}

impl RandomShareGenerationHelper {
    #[must_use]
    pub fn init(rng: Participant, identity: HelperIdentity) -> Self {
        Self { rng, identity }
    }

    #[must_use]
    pub fn gen_random_binary(&mut self) -> ReplicatedBinarySecretSharing {
        let (left, right) = self.rng.next_bits();
        ReplicatedBinarySecretSharing::construct(Fp2::from(left), Fp2::from(right))
    }

    #[must_use]
    pub fn split_binary(
        &self,
        random_binary: ReplicatedBinarySecretSharing,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ) {
        match self.identity {
            HelperIdentity::H1 => (
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(random_binary.0.val()),
                    Fp31::from(0_u8),
                ),
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(0_u8),
                    Fp31::from(random_binary.1.val()),
                ),
                ReplicatedFp31SecretSharing::construct(Fp31::from(0_u8), Fp31::from(0_u8)),
            ),
            HelperIdentity::H2 => (
                ReplicatedFp31SecretSharing::construct(Fp31::from(0_u8), Fp31::from(0_u8)),
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(random_binary.0.val()),
                    Fp31::from(0_u8),
                ),
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(0_u8),
                    Fp31::from(random_binary.1.val()),
                ),
            ),
            HelperIdentity::H3 => (
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(0_u8),
                    Fp31::from(random_binary.1.val()),
                ),
                ReplicatedFp31SecretSharing::construct(Fp31::from(0_u8), Fp31::from(0_u8)),
                ReplicatedFp31SecretSharing::construct(
                    Fp31::from(random_binary.0.val()),
                    Fp31::from(0_u8),
                ),
            ),
        }
    }

    #[must_use]
    pub fn get_share_of_one(&self) -> ReplicatedFp31SecretSharing {
        match self.identity {
            HelperIdentity::H1 => {
                ReplicatedFp31SecretSharing::construct(Fp31::from(1_u8), Fp31::from(0_u8))
            }
            HelperIdentity::H2 => {
                ReplicatedFp31SecretSharing::construct(Fp31::from(0_u8), Fp31::from(0_u8))
            }
            HelperIdentity::H3 => {
                ReplicatedFp31SecretSharing::construct(Fp31::from(0_u8), Fp31::from(1_u8))
            }
        }
    }

    #[must_use]
    pub fn convert_shares_step_1(
        input: u64,
        r_shares: &[(ReplicatedBinarySecretSharing, ReplicatedFp31SecretSharing)],
    ) -> (Vec<ReplicatedFp31SecretSharing>, BitVec) {
        let mut bit_vec = BitVec::from_bytes(&input.to_be_bytes());
        for i in 0..64 {
            let r_binary_shares = r_shares[i].0;
            bit_vec.set(i, bit_vec[i] ^ (r_binary_shares.0 == Fp2::from(true)));
        }
        (r_shares.iter().map(|x| x.1).collect(), bit_vec)
    }

    #[must_use]
    pub fn convert_shares_step_2(
        &self,
        input_xor_r: &BitVec,
        r_shares: &[ReplicatedFp31SecretSharing],
    ) -> Vec<ReplicatedFp31SecretSharing> {
        let mut output = Vec::with_capacity(input_xor_r.len());
        for i in 0..input_xor_r.len() {
            let share = if input_xor_r[i] {
                self.get_share_of_one() - r_shares[i]
            } else {
                r_shares[i]
            };
            output.push(share);
        }
        output
    }

    pub fn gen_batch_of_r_step_1(&mut self, idx: u128) -> (Vec<IntermediateState1>, Vec<Fp31>) {
        let mut idx = idx;

        let mut intermediate_state = Vec::with_capacity(64);
        let mut d_values = Vec::with_capacity(64);

        for _i in 0..64 {
            let r_binary = self.gen_random_binary();
            let r_shares = self.split_binary(r_binary);

            let (r1_x_r2, d) = match self.identity {
                HelperIdentity::H1 => r_shares
                    .0
                    .mult_step1(r_shares.1, &self.rng, idx, true, false),
                HelperIdentity::H2 => r_shares
                    .0
                    .mult_step1(r_shares.1, &self.rng, idx, false, false),
                HelperIdentity::H3 => r_shares
                    .0
                    .mult_step1(r_shares.1, &self.rng, idx, false, true),
            };

            intermediate_state.push(IntermediateState1 {
                r_binary,
                r_shares,
                r1_x_r2,
            });
            d_values.push(d);

            idx += 1;
        }
        (intermediate_state, d_values)
    }

    #[must_use]
    pub fn gen_batch_of_r_step_2(
        &self,
        intermediate_state: &[IntermediateState1],
        d_values: &[Fp31],
        idx: u128,
    ) -> (Vec<IntermediateState2>, Vec<Fp31>) {
        let mut idx = idx;

        let mut next_intermediate_state = Vec::with_capacity(intermediate_state.len());
        let mut next_d_values = Vec::with_capacity(intermediate_state.len());

        for i in 0..intermediate_state.len() {
            let (r1, r2, r3) = intermediate_state[i].r_shares;
            let partial_r1_x_r2 = intermediate_state[i].r1_x_r2;

            let r1_xor_r2 = match self.identity {
                HelperIdentity::H1 | HelperIdentity::H3 => {
                    r1.xor_step2(r2, partial_r1_x_r2, Fp31::from(0_u8))
                }
                HelperIdentity::H2 => r1.xor_step2(r2, partial_r1_x_r2, d_values[i]),
            };

            let (r1_xor_r2_x_r3, d) = match self.identity {
                HelperIdentity::H1 => (r1_xor_r2.mult_step1(r3, &self.rng, idx, false, true)),
                HelperIdentity::H2 => (r1_xor_r2.mult_step1(r3, &self.rng, idx, true, true)),
                HelperIdentity::H3 => (r1_xor_r2.mult_step1(r3, &self.rng, idx, true, false)),
            };

            next_intermediate_state.push(IntermediateState2 {
                r_binary: intermediate_state[i].r_binary,
                r1_xor_r2,
                r3,
                r1_xor_r2_x_r3,
            });
            next_d_values.push(d);

            idx += 1;
        }
        (next_intermediate_state, next_d_values)
    }

    #[must_use]
    pub fn gen_batch_of_r_step_3(
        &self,
        intermediate_state: &[IntermediateState2],
        d_values: &[Fp31],
    ) -> Vec<(ReplicatedBinarySecretSharing, ReplicatedFp31SecretSharing)> {
        let mut r_pairs = Vec::with_capacity(intermediate_state.len());

        for i in 0..intermediate_state.len() {
            let r1_xor_r2 = intermediate_state[i].r1_xor_r2;
            let r3 = intermediate_state[i].r3;
            let r1_xor_r2_x_r3 = intermediate_state[i].r1_xor_r2_x_r3;

            let r1_xor_r2_xor_r3 = match self.identity {
                HelperIdentity::H1 | HelperIdentity::H3 => {
                    r1_xor_r2.xor_step2(r3, r1_xor_r2_x_r3, d_values[i])
                }
                HelperIdentity::H2 => r1_xor_r2.xor_step2(r3, r1_xor_r2_x_r3, Fp31::from(0_u8)),
            };

            r_pairs.push((intermediate_state[i].r_binary, r1_xor_r2_xor_r3));
        }

        r_pairs
    }
}

#[cfg(test)]
mod tests {
    use crate::modulus_convert::{RandomShareGenerationHelper, ReplicatedFp31SecretSharing};

    use crate::field::Fp31;
    use crate::prss::{Participant, ParticipantSetup};
    use bit_vec::BitVec;
    use rand::thread_rng;
    use rand::Rng;

    use super::HelperIdentity;

    fn secret_share(
        a: u8,
        b: u8,
        c: u8,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ) {
        (
            ReplicatedFp31SecretSharing::construct(Fp31::from(a), Fp31::from(b)),
            ReplicatedFp31SecretSharing::construct(Fp31::from(b), Fp31::from(c)),
            ReplicatedFp31SecretSharing::construct(Fp31::from(c), Fp31::from(a)),
        )
    }

    // Yeah, yeah... too many arguments... but it's just a test
    #[allow(clippy::too_many_arguments)]
    pub fn multiply_secret_shares(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a1: ReplicatedFp31SecretSharing,
        a2: ReplicatedFp31SecretSharing,
        a3: ReplicatedFp31SecretSharing,
        b1: ReplicatedFp31SecretSharing,
        b2: ReplicatedFp31SecretSharing,
        b3: ReplicatedFp31SecretSharing,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ) {
        let (h1_res, d1) = a1.mult_step1(b1, &h1.rng, 1, true, true);
        let (h2_res, d2) = a2.mult_step1(b2, &h2.rng, 1, true, true);
        let (h3_res, d3) = a3.mult_step1(b3, &h3.rng, 1, true, true);

        (
            ReplicatedFp31SecretSharing::mult_step2(h1_res, d3),
            ReplicatedFp31SecretSharing::mult_step2(h2_res, d1),
            ReplicatedFp31SecretSharing::mult_step2(h3_res, d2),
        )
    }

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

    // Yeah, yeah... too many arguments... but it's just a test
    #[allow(clippy::too_many_arguments)]
    fn xor_secret_shares(
        h1: &RandomShareGenerationHelper,
        h2: &RandomShareGenerationHelper,
        h3: &RandomShareGenerationHelper,
        a1: ReplicatedFp31SecretSharing,
        a2: ReplicatedFp31SecretSharing,
        a3: ReplicatedFp31SecretSharing,
        b1: ReplicatedFp31SecretSharing,
        b2: ReplicatedFp31SecretSharing,
        b3: ReplicatedFp31SecretSharing,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
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
        res1: ReplicatedFp31SecretSharing,
        res2: ReplicatedFp31SecretSharing,
        res3: ReplicatedFp31SecretSharing,
    ) {
        assert_eq!(res1.1, res2.0);
        assert_eq!(res2.1, res3.0);
        assert_eq!(res3.1, res1.0);
    }

    fn assert_secret_shared_value(
        a1: ReplicatedFp31SecretSharing,
        a2: ReplicatedFp31SecretSharing,
        a3: ReplicatedFp31SecretSharing,
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
        let (res1, res2, res3) = multiply_secret_shares(h1, h2, h3, a1, a2, a3, b1, b2, b3);

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
        let (h1, h2, h3) = make_three();

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

        let res1 = a1.times(Fp31::from(c));
        let res2 = a2.times(Fp31::from(c));
        let res3 = a3.times(Fp31::from(c));

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
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        b: (
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        rng1: &Participant,
        rng2: &Participant,
        rng3: &Participant,
        idx: u128,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
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

    fn xor_step1_optimized(
        a: (
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        b: (
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        rng1: &Participant,
        rng2: &Participant,
        rng3: &Participant,
        idx: u128,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ) {
        let (c1, d1) = a.0.mult_step1(b.0, rng1, idx, true, false);
        let (c2, _) = a.1.mult_step1(b.1, rng2, idx, false, false);
        let (c3, _) = a.2.mult_step1(b.2, rng3, idx, false, true);

        (
            a.0.xor_step2(b.0, c1, Fp31::from(0_u8)),
            a.1.xor_step2(b.1, c2, d1),
            a.2.xor_step2(b.2, c3, Fp31::from(0_u8)),
        )
    }

    fn xor_step2_optimized(
        a: (
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        b: (
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
            ReplicatedFp31SecretSharing,
        ),
        rng1: &Participant,
        rng2: &Participant,
        rng3: &Participant,
        idx: u128,
    ) -> (
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
        ReplicatedFp31SecretSharing,
    ) {
        let (c1, _) = a.0.mult_step1(b.0, rng1, idx, false, true);
        let (c2, d2) = a.1.mult_step1(b.1, rng2, idx, true, true);
        let (c3, d3) = a.2.mult_step1(b.2, rng3, idx, true, false);

        (
            a.0.xor_step2(b.0, c1, d3),
            a.1.xor_step2(b.1, c2, Fp31::from(0_u8)),
            a.2.xor_step2(b.2, c3, d2),
        )
    }

    #[test]
    fn test_three_helpers() {
        let (mut h1, mut h2, mut h3) = self::make_three();

        let mut index: u128 = 0;

        for _i in 0..100 {
            let r_binary = (
                h1.gen_random_binary(),
                h2.gen_random_binary(),
                h3.gen_random_binary(),
            );
            let h1_split = h1.split_binary(r_binary.0);
            let h2_split = h2.split_binary(r_binary.1);
            let h3_split = h3.split_binary(r_binary.2);

            // validate r1
            assert_valid_secret_sharing(h1_split.0, h2_split.0, h3_split.0);
            assert_secret_shared_value(h1_split.0, h2_split.0, h3_split.0, r_binary.0 .0.val());

            // validate r2
            assert_valid_secret_sharing(h1_split.1, h2_split.1, h3_split.1);
            assert_secret_shared_value(h1_split.1, h2_split.1, h3_split.1, r_binary.1 .0.val());

            // validate r3
            assert_valid_secret_sharing(h1_split.2, h2_split.2, h3_split.2);
            assert_secret_shared_value(h1_split.2, h2_split.2, h3_split.2, r_binary.2 .0.val());

            // Compute r1 ^ r2
            let r1_xor_r2 = xor(
                (h1_split.0, h2_split.0, h3_split.0),
                (h1_split.1, h2_split.1, h3_split.1),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index,
            );
            index += 1;

            // validate r1 ^ r2
            assert_valid_secret_sharing(r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2);
            assert_secret_shared_value(
                r1_xor_r2.0,
                r1_xor_r2.1,
                r1_xor_r2.2,
                (r_binary.0 .0 + r_binary.1 .0).val(),
            );

            // Compute (r1 ^ r2) ^ r3
            let r1_xor_r2_xor_r3 = xor(
                (r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2),
                (h1_split.2, h2_split.2, h3_split.2),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index,
            );
            index += 1;

            // validate (r1 ^ r2) ^ r3
            assert_valid_secret_sharing(r1_xor_r2_xor_r3.0, r1_xor_r2_xor_r3.1, r1_xor_r2_xor_r3.2);
            assert_secret_shared_value(
                r1_xor_r2_xor_r3.0,
                r1_xor_r2_xor_r3.1,
                r1_xor_r2_xor_r3.2,
                (r_binary.0 .0 + r_binary.1 .0 + r_binary.2 .0).val(),
            );
        }
    }

    #[test]
    fn test_three_helpers_optimized() {
        let (mut h1, mut h2, mut h3) = self::make_three();

        let mut index: u128 = 0;

        for _i in 0..100 {
            let r_binary = (
                h1.gen_random_binary(),
                h2.gen_random_binary(),
                h3.gen_random_binary(),
            );
            let h1_split = h1.split_binary(r_binary.0);
            let h2_split = h2.split_binary(r_binary.1);
            let h3_split = h3.split_binary(r_binary.2);

            // validate r1
            assert_valid_secret_sharing(h1_split.0, h2_split.0, h3_split.0);
            assert_secret_shared_value(h1_split.0, h2_split.0, h3_split.0, r_binary.0 .0.val());

            // validate r2
            assert_valid_secret_sharing(h1_split.1, h2_split.1, h3_split.1);
            assert_secret_shared_value(h1_split.1, h2_split.1, h3_split.1, r_binary.1 .0.val());

            // validate r3
            assert_valid_secret_sharing(h1_split.2, h2_split.2, h3_split.2);
            assert_secret_shared_value(h1_split.2, h2_split.2, h3_split.2, r_binary.2 .0.val());

            // Compute r1 ^ r2
            let r1_xor_r2 = xor_step1_optimized(
                (h1_split.0, h2_split.0, h3_split.0),
                (h1_split.1, h2_split.1, h3_split.1),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index,
            );
            index += 1;

            // validate r1 ^ r2
            assert_valid_secret_sharing(r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2);
            assert_secret_shared_value(
                r1_xor_r2.0,
                r1_xor_r2.1,
                r1_xor_r2.2,
                (r_binary.0 .0 + r_binary.1 .0).val(),
            );

            // Compute (r1 ^ r2) ^ r3
            let r1_xor_r2_xor_r3 = xor_step2_optimized(
                (r1_xor_r2.0, r1_xor_r2.1, r1_xor_r2.2),
                (h1_split.2, h2_split.2, h3_split.2),
                &h1.rng,
                &h2.rng,
                &h3.rng,
                index,
            );
            index += 1;

            // validate (r1 ^ r2) ^ r3
            assert_valid_secret_sharing(r1_xor_r2_xor_r3.0, r1_xor_r2_xor_r3.1, r1_xor_r2_xor_r3.2);
            assert_secret_shared_value(
                r1_xor_r2_xor_r3.0,
                r1_xor_r2_xor_r3.1,
                r1_xor_r2_xor_r3.2,
                (r_binary.0 .0 + r_binary.1 .0 + r_binary.2 .0).val(),
            );
        }
    }

    #[test]
    fn test_batch_generation_and_share_conversion() {
        let (mut h1, mut h2, mut h3) = self::make_three();

        let mut index: u128 = 1000;

        let (h1_local_state, d1) = h1.gen_batch_of_r_step_1(index);
        #[allow(clippy::similar_names)]
        let (h2_local_state, _) = h2.gen_batch_of_r_step_1(index);
        #[allow(clippy::similar_names)]
        let (h3_local_state, _) = h3.gen_batch_of_r_step_1(index);

        index += 64; // batch size is hard-coded to 64

        #[allow(clippy::similar_names)]
        let (h1_local_state, _) = h1.gen_batch_of_r_step_2(&h1_local_state, &[], index);
        #[allow(clippy::similar_names)]
        let (h2_local_state, d2) = h2.gen_batch_of_r_step_2(&h2_local_state, &d1, index);
        #[allow(clippy::similar_names)]
        let (h3_local_state, d3) = h3.gen_batch_of_r_step_2(&h3_local_state, &[], index);

        let pairs1 = h1.gen_batch_of_r_step_3(&h1_local_state, &d3);
        #[allow(clippy::similar_names)]
        let pairs2 = h2.gen_batch_of_r_step_3(&h2_local_state, &[]);
        #[allow(clippy::similar_names)]
        let pairs3 = h3.gen_batch_of_r_step_3(&h3_local_state, &d2);

        for i in 0..pairs1.len() {
            assert_valid_secret_sharing(pairs1[i].1, pairs2[i].1, pairs3[i].1);
            assert_secret_shared_value(
                pairs1[i].1,
                pairs2[i].1,
                pairs3[i].1,
                (pairs1[i].0 .0 + pairs2[i].0 .0 + pairs3[i].0 .0).val(),
            );
        }

        let secret_value: u64 = thread_rng().gen_range(0..u64::MAX);

        // Personally, I prefer to think about binary numbers in big-endian fashion
        let bits_of_secret = BitVec::from_bytes(&secret_value.to_be_bytes());

        let share_1 = thread_rng().gen_range(0..u64::MAX);
        let share_2 = thread_rng().gen_range(0..u64::MAX);
        let share_3 = (secret_value ^ share_1) ^ share_2;

        let (is1, m1) = RandomShareGenerationHelper::convert_shares_step_1(share_1, &pairs1);
        let (is2, m2) = RandomShareGenerationHelper::convert_shares_step_1(share_2, &pairs2);
        let (is3, m3) = RandomShareGenerationHelper::convert_shares_step_1(share_3, &pairs3);

        // All helpers send their values to Helper 1, who XORs them all together
        // to reveal the bitwise input XOR r
        // Helper 1 can reveal this value to the other helpers
        let mut input_xor_r: BitVec = m1;
        for i in 0..input_xor_r.len() {
            input_xor_r.set(i, input_xor_r[i] ^ m2[i] ^ m3[i]);
        }

        let bitwise_shares1 = h1.convert_shares_step_2(&input_xor_r, &is1);
        let bitwise_shares2 = h2.convert_shares_step_2(&input_xor_r, &is2);
        let bitwise_shares3 = h3.convert_shares_step_2(&input_xor_r, &is3);

        for i in 0..bitwise_shares1.len() {
            assert_valid_secret_sharing(bitwise_shares1[i], bitwise_shares2[i], bitwise_shares3[i]);
            assert_secret_shared_value(
                bitwise_shares1[i],
                bitwise_shares2[i],
                bitwise_shares3[i],
                u128::from(bits_of_secret[i]),
            );
        }
    }
}
