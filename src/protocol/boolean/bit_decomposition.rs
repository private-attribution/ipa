use super::bitwise_lt::BitwiseLessThan;
use super::bitwise_sum::BitwiseSum;
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::protocol::boolean::local_secret_shared_bits;
use crate::protocol::boolean::solved_bits::SolvedBits;
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::reveal::Reveal;
use crate::protocol::RecordId;
use crate::secret_sharing::Replicated;

/// This is an implementation of "3. Bit-Decomposition" from I. Damgård et al..
///
/// It takes an input `[a] ∈ F_p` and outputs its bitwise additive share
/// `[a]_B = ([a]_0,...,[a]_l-1)` where `[a]_i ∈ F_p`.
///
/// 3. Bit-Decomposition
/// "Unconditionally Secure Constant-Rounds Multi-party Computation for Equality, Comparison, Bits, and Exponentiation"
/// I. Damgård et al.
pub struct BitDecomposition {}

impl BitDecomposition {
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a_p: &Replicated<F>,
    ) -> Result<Vec<Replicated<F>>, Error> {
        // step 1 in the paper is just describing the input, `[a]_p` where `a ∈ F_p`

        // Step 2. Generate random bitwise shares
        let r = SolvedBits::execute(ctx.narrow(&Step::GenerateRandomBits), record_id).await?;
        // Would like to do something like below. Where should I add the `RandomBitsGenerator`?
        // let r = ctx.random_bits_generator.take_one().await?;
        let r = r.expect("SolvedBits aborted");

        // Step 3, 4. Reveal c = [a - b]_p
        let c = ctx
            .narrow(&Step::RevealAMinusB)
            .reveal(record_id, &(a_p - &r.b_p))
            .await?;
        let c_b = local_secret_shared_bits(c.as_u128(), ctx.role());

        // Step 5. Add back [b] bitwise. [d]_B = BitwiseSum(c, [b]_B) where d ∈ Z
        //
        // `BitwiseSum` outputs `l + 1` bits, so [d]_B is (l + 1)-bit long.
        let d_b = BitwiseSum::execute(ctx.narrow(&Step::AddBtoC), record_id, &c_b, &r.b_b).await?;

        // Step 6. p <? d
        let p_b = local_secret_shared_bits(F::PRIME.into(), ctx.role());
        let q_p = BitwiseLessThan::execute(ctx.narrow(&Step::IsPLessThanD), record_id, &p_b, &d_b)
            .await?;

        // Step 7. a bitwise scalar value `f_B = bits(2^l - p)`
        let l = F::Integer::BITS;
        let x = 2_u128.pow(l) - F::PRIME.into();
        let f_b = (0..l).map(|i| F::from(x >> i & 1));

        // Step 8, 9. [g_i] = [q] * f_i
        let g_b = f_b
            .into_iter()
            .map(|f_bit| q_p.clone() * f_bit)
            .collect::<Vec<_>>();

        // Step 10. [h]_B = [d + g]_B, where [h]_B = ([h]_0,...[h]_(l+1))
        //
        // Again, `BitwiseSum` outputs `l + 1` bits. Since [d]_B is already
        // `l + 1` bit long, [h]_B will be `l + 2`-bit long.
        let h_b = BitwiseSum::execute(ctx.narrow(&Step::AddDtoG), record_id, &d_b, &g_b).await?;

        // Step 11. [a]_B = ([h]_0,...[h]_(l-1))
        let a_b = h_b[0..l as usize].to_vec();

        Ok(a_b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    GenerateRandomBits,
    RevealAMinusB,
    AddBtoC,
    IsPLessThanD,
    AddDtoG,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::GenerateRandomBits => "generate_random_bits",
            Self::RevealAMinusB => "reveal_a_minus_b",
            Self::AddBtoC => "add_b_to_c",
            Self::IsPLessThanD => "is_p_less_than_d",
            Self::AddDtoG => "add_d_to_g",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitDecomposition;
    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime, Int},
        protocol::context::SemiHonestContext,
        protocol::{QueryId, RecordId},
        test_fixture::{
            bits_to_value, join3, make_contexts, make_world, share, validate_and_reconstruct,
            TestWorld,
        },
    };
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng, Rng};

    async fn bit_decomposition<F: Field>(
        ctx: [SemiHonestContext<'_, F>; 3],
        record_id: RecordId,
        a: F,
    ) -> Result<Vec<F>, Error>
    where
        Standard: Distribution<F>,
    {
        let [c0, c1, c2] = ctx;
        let mut rand = StepRng::new(1, 1);

        let s = share(a, &mut rand);

        let result = join3(
            BitDecomposition::execute(c0, record_id, &s[0]),
            BitDecomposition::execute(c1, record_id, &s[1]),
            BitDecomposition::execute(c2, record_id, &s[2]),
        )
        .await;

        // bit-decomposed values must have the same bit length of the target field
        assert_eq!(F::Integer::BITS as usize, result[0].len());
        assert_eq!(F::Integer::BITS as usize, result[1].len());
        assert_eq!(F::Integer::BITS as usize, result[2].len());

        let bits = (0..result[0].len())
            .map(|i| validate_and_reconstruct(&result[0][i], &result[1][i], &result[2][i]))
            .collect::<Vec<_>>();

        Ok(bits)
    }

    #[ignore]
    #[tokio::test]
    pub async fn fp31() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..10 {
            let input = rng.gen::<Fp31>();
            let result = bit_decomposition(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(i),
                input,
            )
            .await?;

            if input.as_u128() == 0 {
                // if the protocol's input is 0, the output could either be
                // a bitwise sharing of 0 or the prime (in the integers).
                let x = bits_to_value(&result);
                assert!(x == 0 || x == u128::from(Fp31::PRIME));
            } else {
                // otherwise, the reconstructed integer (not the field) must
                // be in the range of the field `0..p`.
                assert_eq!(input.as_u128(), bits_to_value(&result));
            }
        }

        Ok(())
    }

    #[tokio::test]
    pub async fn fp32_bit_prime() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp32BitPrime>(&world);
        let [c0, c1, c2] = ctx;
        let mut rng = rand::thread_rng();

        for i in 0..2 {
            let input = rng.gen::<Fp32BitPrime>();
            let result = bit_decomposition(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(i),
                input,
            )
            .await?;

            if input.as_u128() == 0 {
                // if the protocol's input is 0, the output could either be
                // a bitwise sharing of 0 or the prime (in the integers).
                let x = bits_to_value(&result);
                assert!(x == 0 || x == u128::from(Fp32BitPrime::PRIME));
            } else {
                // otherwise, the reconstructed integer (not the field) must
                // be in the range of the field `0..p`.
                assert_eq!(input.as_u128(), bits_to_value(&result));
            }
        }

        Ok(())
    }
}
