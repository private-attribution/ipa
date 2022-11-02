use crate::{
    error::BoxError,
    ff::{BinaryField, Field},
    helpers::Identity,
    protocol::{
        context::ProtocolContext,
        modulus_conversion::specialized_mul::{
            multiply_one_share_mostly_zeroes, multiply_two_shares_mostly_zeroes,
        },
        RecordId,
    },
    secret_sharing::Replicated,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    Xor1,
    Xor2,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::Xor1 => "xor1",
            Self::Xor2 => "xor2",
        }
    }
}

///
/// This file is an implementation of Algorithm D.3 from <https://eprint.iacr.org/2018/387.pdf>
/// "Efficient generation of a pair of random shares for small number of parties"
///
/// In order to convert from a 3-party secret sharing in `Z_2`, to a 3-party replicated
/// secret sharing in `Z_p` (where p > 2), we need to generate two secret sharings of
/// a random value `r` ∈ {0, 1}, where none of the helper parties know the value of `r`.
/// With Psuedo-random secret-sharing (PRSS), we can generate a 3-party replicated
/// secret-sharing of unknown value 'r' without any interaction between the helpers.
/// We just generate 3 random binary inputs, where each helper is aware of just two.
///
/// This `DoubleRandom` protocol takes as input such a 3-way random binary replicated secret-sharing,
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
#[derive(Debug)]
pub struct DoubleRandom {}

impl DoubleRandom {
    ///
    /// Internal use only.
    /// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
    ///
    fn local_secret_share<B: BinaryField, F: Field>(
        input: Replicated<B>,
        channel_identity: Identity,
    ) -> (Replicated<F>, Replicated<F>, Replicated<F>) {
        let (left, right) = input.as_tuple();
        match channel_identity {
            Identity::H1 => (
                Replicated::new(F::from(left.as_u128()), F::ZERO),
                Replicated::new(F::ZERO, F::from(right.as_u128())),
                Replicated::new(F::ZERO, F::ZERO),
            ),
            Identity::H2 => (
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(left.as_u128()), F::ZERO),
                Replicated::new(F::ZERO, F::from(right.as_u128())),
            ),
            Identity::H3 => (
                Replicated::new(F::ZERO, F::from(right.as_u128())),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(left.as_u128()), F::ZERO),
            ),
        }
    }

    ///
    /// Internal use only
    /// When both inputs are known to be secret share of either '1' or '0',
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
        ctx: ProtocolContext<'_, F>,
        record_id: RecordId,
        a: Replicated<F>,
        b: Replicated<F>,
    ) -> Result<Replicated<F>, BoxError> {
        let result = multiply_two_shares_mostly_zeroes(ctx, record_id, a, b).await?;

        Ok(a + b - (result * F::from(2)))
    }

    ///
    /// Internal use only
    /// When both inputs are known to be secret share of either '1' or '0',
    /// XOR can be computed as:
    /// a + b - 2*a*b
    ///
    /// This variant is only to be used for the first XOR
    /// Where helper 1 has shares:
    /// b: (0, 0)
    ///
    /// And helper 2 has shares:
    /// (0, x3)
    ///
    /// And helper 3 has shares:
    /// (x3, 0)
    async fn xor_specialized_2<F: Field>(
        ctx: ProtocolContext<'_, F>,
        record_id: RecordId,
        a: Replicated<F>,
        b: Replicated<F>,
    ) -> Result<Replicated<F>, BoxError> {
        let result = multiply_one_share_mostly_zeroes(ctx, record_id, a, b).await?;

        Ok(a + b - (result * F::from(2)))
    }

    ///
    /// This will convert the input (a random, replicated binary secret sharing
    /// of unknown number 'r') into a random secret sharing of the same value in `Z_p`
    /// where the caller can select the output Field.
    #[allow(dead_code)]
    pub async fn execute<B: BinaryField, F: Field>(
        ctx: ProtocolContext<'_, F>,
        record_id: RecordId,
        random_sharing: Replicated<B>,
    ) -> Result<Replicated<F>, BoxError> {
        let (sh0, sh1, sh2) = Self::local_secret_share(random_sharing, ctx.role());

        let sh0_xor_sh1 =
            Self::xor_specialized_1(ctx.narrow(&Step::Xor1), record_id, sh0, sh1).await?;
        Self::xor_specialized_2(ctx.narrow(&Step::Xor2), record_id, sh0_xor_sh1, sh2).await
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        error::BoxError,
        ff::{Field, Fp2, Fp31},
        protocol::{modulus_conversion::double_random::DoubleRandom, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{make_contexts, make_world, validate_and_reconstruct},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;

    #[tokio::test]
    pub async fn gen_random() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();

        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let ctx0 = &context[0];
        let ctx1 = &context[1];
        let ctx2 = &context[2];

        let mut bools: Vec<u128> = Vec::with_capacity(40);
        let mut futures = Vec::with_capacity(40);

        for i in 0..40_u32 {
            let b0 = rng.gen::<bool>();
            let b1 = rng.gen::<bool>();
            let b2 = rng.gen::<bool>();
            bools.push(u128::from((b0 ^ b1) ^ b2));

            let bit_number = format!("bit{}", i);

            let record_id = RecordId::from(i);

            futures.push(try_join_all(vec![
                DoubleRandom::execute(
                    ctx0.narrow(&bit_number),
                    record_id,
                    Replicated::new(Fp2::from(b0), Fp2::from(b1)),
                ),
                DoubleRandom::execute(
                    ctx1.narrow(&bit_number),
                    record_id,
                    Replicated::new(Fp2::from(b1), Fp2::from(b2)),
                ),
                DoubleRandom::execute(
                    ctx2.narrow(&bit_number),
                    record_id,
                    Replicated::new(Fp2::from(b2), Fp2::from(b0)),
                ),
            ]));
        }

        let results = try_join_all(futures).await?;

        for i in 0..40 {
            let result_shares = &results[i];
            let output_share: Fp31 =
                validate_and_reconstruct((result_shares[0], result_shares[1], result_shares[2]));

            assert_eq!(output_share.as_u128(), bools[i]);
        }
        Ok(())
    }
}
