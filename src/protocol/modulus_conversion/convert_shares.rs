use super::specialized_mul::{multiply_one_share_mostly_zeroes, multiply_two_shares_mostly_zeroes};
use crate::{
    error::Error,
    ff::{BinaryField, Field, Fp2},
    helpers::Role,
    protocol::{context::Context, RecordId},
    secret_sharing::Replicated,
};

use crate::protocol::context::SemiHonestContext;
use futures::future::try_join_all;
use std::iter::{repeat, zip};

#[derive(Clone, Copy, Debug)]
pub struct XorShares {
    num_bits: u8,
    packed_bits_left: u64,
    packed_bits_right: u64,
}

impl XorShares {
    pub fn new(num_bits: u8, packed_bits_left: u64, packed_bits_right: u64) -> Self {
        Self {
            num_bits,
            packed_bits_left,
            packed_bits_right,
        }
    }
}

pub struct ConvertShares {
    input: XorShares,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    Xor1,
    Xor2,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::Xor1 => "xor1",
            Self::Xor2 => "xor2",
        }
    }
}

///
/// This takes a replicated secret sharing of a sequence of bits (in a packed format)
/// and converts them, one bit-place at a time, to secret sharings of that bit value (either one or zero) in the target field.
///
/// This file is somewhat inspired by Algorithm D.3 from <https://eprint.iacr.org/2018/387.pdf>
/// "Efficient generation of a pair of random shares for small number of parties"
///
/// This protocol takes as input such a 3-way random binary replicated secret-sharing,
/// and produces a 3-party replicated secret-sharing of the same value in a target field
/// of the caller's choosing.
/// Example:
/// For input binary sharing: (0, 1, 1) -> which is a sharing of 0 in `Z_2`
/// sample output in `Z_31` could be: (22, 19, 21) -> also a sharing of 0 in `Z_31`
/// This transformation is simple:
/// The original can be conceived of as r = b0 ⊕ b1 ⊕ b2
/// Each of the 3 bits can be trivially converted into a 3-way secret sharing in `Z_p`
/// So if the second bit is a '1', we can make a 3-way secret sharing of '1' in `Z_p`
/// as (0, 1, 0).
/// Now we simply need to XOR these three sharings together in `Z_p`. This is easy because
/// we know the secret-shared values are all either 0, or 1. As such, the XOR operation
/// is equivalent to fn xor(a, b) { a + b - 2*a*b }
impl ConvertShares {
    pub fn new(input: XorShares) -> Self {
        Self { input }
    }

    ///
    /// Internal use only.
    /// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
    ///
    fn local_secret_share<B: BinaryField, F: Field>(
        input: &Replicated<B>,
        helper_role: Role,
    ) -> [Replicated<F>; 3] {
        let (left, right) = input.as_tuple();
        match helper_role {
            Role::H1 => [
                Replicated::new(F::from(left.as_u128()), F::ZERO),
                Replicated::new(F::ZERO, F::from(right.as_u128())),
                Replicated::new(F::ZERO, F::ZERO),
            ],
            Role::H2 => [
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(left.as_u128()), F::ZERO),
                Replicated::new(F::ZERO, F::from(right.as_u128())),
            ],
            Role::H3 => [
                Replicated::new(F::ZERO, F::from(right.as_u128())),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(left.as_u128()), F::ZERO),
            ],
        }
    }

    ///
    /// Internal use only
    /// When both inputs are known to be secret shares of either '1' or '0',
    /// XOR can be computed as:
    /// a + b - 2*a*b
    ///
    /// This variant is only to be used for the first XOR
    /// Where helper 1 has shares:
    /// a: (x1, 0) and b: (0, x2)
    ///
    /// And helper 2 has shares:
    /// a: (0, 0) and b: (x2, 0)
    ///
    /// And helper 3 has shares:
    /// a: (0, x1) and b: (0, 0)
    async fn xor_specialized_1<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &Replicated<F>,
        b: &Replicated<F>,
    ) -> Result<Replicated<F>, Error> {
        let result = multiply_two_shares_mostly_zeroes(ctx, record_id, a, b).await?;

        Ok(a + b - &(result * F::from(2)))
    }

    ///
    /// Internal use only
    /// When both inputs are known to be secret share of either '1' or '0',
    /// XOR can be computed as:
    /// a + b - 2*a*b
    ///
    /// This variant is only to be used for the second XOR
    /// Where helper 1 has shares:
    /// b: (0, 0)
    ///
    /// And helper 2 has shares:
    /// (0, x3)
    ///
    /// And helper 3 has shares:
    /// (x3, 0)
    async fn xor_specialized_2<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &Replicated<F>,
        b: &Replicated<F>,
    ) -> Result<Replicated<F>, Error> {
        let result = multiply_one_share_mostly_zeroes(ctx, record_id, a, b).await?;

        Ok(a + b - &(result * F::from(2)))
    }

    pub async fn execute_one_bit<F: Field>(
        &self,
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        bit_index: u8,
    ) -> Result<Replicated<F>, Error> {
        assert!(bit_index < self.input.num_bits);

        let input = Replicated::new(
            Fp2::from(self.input.packed_bits_left & (1 << bit_index) != 0),
            Fp2::from(self.input.packed_bits_right & (1 << bit_index) != 0),
        );

        let [sh0, sh1, sh2] = Self::local_secret_share(&input, ctx.role());

        let sh0_xor_sh1 =
            Self::xor_specialized_1(ctx.narrow(&Step::Xor1), record_id, &sh0, &sh1).await?;
        Self::xor_specialized_2(ctx.narrow(&Step::Xor2), record_id, &sh0_xor_sh1, &sh2).await
    }
}

#[allow(clippy::module_name_repetitions)]
/// For a given vector of input shares, this returns a vector of modulus converted replicated shares of
/// `bit_index` of each input.
pub async fn convert_shares_for_a_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[(u64, u64)],
    num_bits: u8,
    bit_index: u8,
) -> Result<Vec<Replicated<F>>, Error> {
    let converted_shares = try_join_all(zip(repeat(ctx), input).enumerate().map(
        |(record_id, (ctx, row))| async move {
            let record_id = RecordId::from(record_id);
            ConvertShares::new(XorShares::new(num_bits, row.0, row.1))
                .execute_one_bit(ctx, record_id, bit_index)
                .await
        },
    ))
    .await?;
    Ok(converted_shares)
}

#[cfg(test)]
mod tests {

    use crate::{
        error::Error,
        ff::{Field, Fp31},
        protocol::{
            modulus_conversion::convert_shares::{ConvertShares, XorShares},
            QueryId, RecordId,
        },
        test_fixture::{validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use std::iter::{repeat, zip};

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        prss_space_number: u8,
    }

    #[tokio::test]
    pub async fn convert_one_bit_of_many_match_keys() -> Result<(), Error> {
        let mut rng = rand::thread_rng();

        let world = TestWorld::new(QueryId);
        let context = world.contexts::<Fp31>();
        let [c0, c1, c2] = context;

        let mask = (1_u64 << 41) - 1; // in binary, a sequence of 40 ones
        let mut match_keys = Vec::with_capacity(1000);
        let mut shared_match_keys = Vec::with_capacity(1000);
        for _ in 0..1000 {
            let match_key: u64 = rng.gen::<u64>() & mask;
            let share_0 = rng.gen::<u64>() & mask;
            let share_1 = rng.gen::<u64>() & mask;
            let share_2 = match_key ^ share_0 ^ share_1;

            match_keys.push(match_key);
            shared_match_keys.push((share_0, share_1, share_2));
        }

        let results = try_join_all(
            zip(
                repeat(c0),
                zip(repeat(c1), zip(repeat(c2), shared_match_keys)),
            )
            .enumerate()
            .map(|(i, (c0, (c1, (c2, shared_match_key))))| async move {
                let (share_0, share_1, share_2) = shared_match_key;
                let record_id = RecordId::from(i);
                try_join_all(vec![
                    ConvertShares::new(XorShares::new(40, share_0, share_1))
                        .execute_one_bit(c0, record_id, 4),
                    ConvertShares::new(XorShares::new(40, share_1, share_2))
                        .execute_one_bit(c1, record_id, 4),
                    ConvertShares::new(XorShares::new(40, share_2, share_0))
                        .execute_one_bit(c2, record_id, 4),
                ])
                .await
            }),
        )
        .await?;

        for (match_key, result) in zip(match_keys, results) {
            let bit_of_match_key = match_key & (1 << 4) != 0;

            let share_of_bit = validate_and_reconstruct(&result[0], &result[1], &result[2]);
            if bit_of_match_key {
                assert_eq!(share_of_bit, Fp31::ONE);
            } else {
                assert_eq!(share_of_bit, Fp31::ZERO);
            }
        }
        Ok(())
    }
}
