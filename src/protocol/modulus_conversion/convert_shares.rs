use crate::{
    error::BoxError,
    helpers::fabric::Network,
    protocol::{
        context::ProtocolContext, modulus_conversion::double_random::DoubleRandom,
        reveal_additive_binary::RevealAdditiveBinary, RecordId,
    },
    secret_sharing::{Field, Replicated},
};
use futures::future::{try_join, try_join_all};

pub struct XorShares {
    num_bits: u8,
    packed_bits: u64,
}

pub struct ConvertShares {
    input: XorShares,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    DoubleRandom,
    BinaryReveal,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::DoubleRandom => "double_random",
            Self::BinaryReveal => "binary_reveal",
        }
    }
}

///
/// This is an implementation of
/// Protocol 5.2 Modulus-conversion protocol from `Z_2^u` to `Z_p`
/// from the paper <https://eprint.iacr.org/2018/387.pdf>
///
/// It works by generating two secret-sharings of a random number `r`,
/// one in `Z_2`, the other in `Z_p`. The sharing in `Z_2` is subtracted
/// from the input and the result is revealed.
///
/// If the revealed result is `0`, that indicates that `r` had the same value
/// as the secret input, so the sharing in `Z_p` is returned.
/// If the revealed result is a `1`, that indicates that `r` was different than
/// the secret input, so a sharing of `1 - r` is returned.
impl ConvertShares {
    #[allow(dead_code)]
    pub fn new(input: XorShares) -> Self {
        Self { input }
    }

    #[allow(dead_code)]
    pub async fn execute<F: Field, N: Network>(
        &self,
        ctx: ProtocolContext<'_, N>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let prss = &ctx.prss();
        let (left, right) = prss.generate_values(record_id);

        let bits = (0..self.input.num_bits).into_iter().map(|i| {
            let b0 = left & (1 << i) != 0;
            let b1 = right & (1 << i) != 0;
            let input = self.input.packed_bits & (1 << i) != 0;
            let input_xor_r = input ^ b0;
            (ctx.narrow(&format!("bit:{}", i)), b0, b1, input_xor_r)
        });

        let futures = bits
            .into_iter()
            .map(|(ctx, b0, b1, input_xor_r)| async move {
                let r_binary = Replicated::new(b0, b1);

                let gen_random_future =
                    DoubleRandom::execute(ctx.narrow(&Step::DoubleRandom), record_id, r_binary);

                let reveal_future = RevealAdditiveBinary::execute(
                    ctx.narrow(&Step::BinaryReveal),
                    record_id,
                    input_xor_r,
                );

                let (r_big_field, revealed_output) =
                    try_join(gen_random_future, reveal_future).await?;

                if revealed_output {
                    Ok(Replicated::<F>::one(ctx.role()) - r_big_field)
                } else {
                    Ok(r_big_field)
                }
            });
        try_join_all(futures).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        protocol::{
            modulus_conversion::convert_shares::{ConvertShares, XorShares},
            QueryId, RecordId,
        },
        secret_sharing::{Field, Fp31},
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        prss_space_number: u8,
    }

    #[tokio::test]
    pub async fn convert_shares() {
        let mut rng = rand::thread_rng();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let [c0, c1, c2] = context;

        let mask = (1_u64 << 41) - 1; // in binary, a sequence of 40 ones
        let match_key: u64 = rng.gen::<u64>() & mask;
        let share_0 = rng.gen::<u64>() & mask;
        let share_1 = rng.gen::<u64>() & mask;
        let share_2 = match_key ^ share_0 ^ share_1;

        let record_id = RecordId::from(0_u32);

        let awaited_futures = try_join_all(vec![
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_0,
            })
            .execute(c0, record_id),
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_1,
            })
            .execute(c1, record_id),
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_2,
            })
            .execute(c2, record_id),
        ])
        .await
        .unwrap();

        let v0 = &awaited_futures[0];
        let v1 = &awaited_futures[1];
        let v2 = &awaited_futures[2];

        for i in 0..40 {
            let bit_of_match_key = match_key & (1 << i) != 0;

            let share_of_bit: Fp31 = validate_and_reconstruct((v0[i], v1[i], v2[i]));
            if bit_of_match_key {
                assert_eq!(share_of_bit, Fp31::ONE);
            } else {
                assert_eq!(share_of_bit, Fp31::ZERO);
            }
        }
    }
}
