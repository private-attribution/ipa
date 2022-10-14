use crate::{
    error::BoxError,
    field::Field,
    helpers::{fabric::Network, prss::SpaceIndex},
    protocol::{
        context::ProtocolContext,
        modulus_conversion::gen_random::{GenRandom, ReplicatedBinary},
        reveal_additive_binary::RevealAdditiveBinary,
        RecordId, Step,
    },
    secret_sharing::Replicated,
};
use futures::future::try_join_all;

pub struct XorShares {
    num_bits: u8,
    packed_bits: u64,
}

pub struct ConvertShares {
    input: XorShares,
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
/// If the revealed result is a `1`, that indicate that `r` was different than
/// the secret nput, so the sharing 1 - the sharing in `Z_p` is returned.
impl ConvertShares {
    #[allow(dead_code)]
    pub fn new(input: XorShares) -> Self {
        Self { input }
    }

    #[allow(dead_code)]
    pub async fn execute<F: Field, S: Step + SpaceIndex, N: Network<S>>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        record_id: RecordId,
        step0: S,
        step1: S,
        step2: S,
        step3: S,
    ) -> Result<Vec<Replicated<F>>, BoxError> {
        let prss = &ctx.participant[step0];
        let (left, right) = prss.generate_values(record_id.into());

        let futures = (0..self.input.num_bits).into_iter().map(|i| async move {
            let inner_record_id = RecordId::from(
                u32::from(record_id) * u32::from(self.input.num_bits) + u32::from(i),
            );
            let b0 = left & (1 << i) != 0;
            let b1 = right & (1 << i) != 0;

            let input = self.input.packed_bits & (1 << i) != 0;

            let input_xor_r = input ^ b0;

            let r_binary = ReplicatedBinary::new(b0, b1);

            let r_big_field: Replicated<F> = GenRandom::new(r_binary)
                .execute(ctx, inner_record_id, step1, step2)
                .await?;

            let revealed_output =
                RevealAdditiveBinary::execute(ctx, step3, inner_record_id, input_xor_r).await?;

            if revealed_output {
                Ok(Replicated::<F>::one(ctx.identity) - r_big_field)
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
        field::{Field, Fp31},
        protocol::{
            modulus_conversion::convert_shares::{ConvertShares, XorShares},
            QueryId, RecordId, SpaceIndex, Step,
        },
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        prss_space_number: u8,
    }

    impl Step for ModulusConversionTestStep {}

    impl SpaceIndex for ModulusConversionTestStep {
        const MAX: usize = 5;

        fn as_usize(&self) -> usize {
            usize::from(self.prss_space_number)
        }
    }

    #[tokio::test]
    pub async fn convert_shares() {
        let mut rng = rand::thread_rng();

        let world: TestWorld<ModulusConversionTestStep> = make_world(QueryId);
        let context = make_contexts(&world);
        let ctx0 = &context[0];
        let ctx1 = &context[1];
        let ctx2 = &context[2];

        let mask = (1_u64 << 41) - 1; // in binary, a sequence of 40 ones
        let match_key: u64 = rng.gen::<u64>() & mask;
        let share_0 = rng.gen::<u64>() & mask;
        let share_1 = rng.gen::<u64>() & mask;
        let share_2 = match_key ^ share_0 ^ share_1;

        let record_id = RecordId::from(0_u32);

        let step1 = ModulusConversionTestStep {
            prss_space_number: 1,
        };
        let step2 = ModulusConversionTestStep {
            prss_space_number: 2,
        };
        let step3 = ModulusConversionTestStep {
            prss_space_number: 3,
        };
        let step4 = ModulusConversionTestStep {
            prss_space_number: 4,
        };

        let awaited_futures = try_join_all(vec![
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_0,
            })
            .execute(ctx0, record_id, step1, step2, step3, step4),
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_1,
            })
            .execute(ctx1, record_id, step1, step2, step3, step4),
            ConvertShares::new(XorShares {
                num_bits: 40,
                packed_bits: share_2,
            })
            .execute(ctx2, record_id, step1, step2, step3, step4),
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
