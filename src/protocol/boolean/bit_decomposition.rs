use super::bitwise_less_than_prime::BitwiseLessThanPrime;
use super::dumb_bitwise_sum::bitwise_sum;
use super::random_bits_generator::RandomBitsGenerator;
use crate::error::Error;
use crate::ff::{Field, Int};
use crate::protocol::boolean::local_secret_shared_bits;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::SecretSharing;

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
    /// Converts the input field value to bitwise secret shares.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    pub async fn execute<F, S, C>(
        ctx: C,
        record_id: RecordId,
        rbg: RandomBitsGenerator<F, S>,
        a_p: &S,
    ) -> Result<Vec<S>, Error>
    where
        F: Field,
        S: SecretSharing<F>,
        C: Context<F, Share = S>,
    {
        // step 1 in the paper is just describing the input, `[a]_p` where `a ∈ F_p`

        // Step 2. Generate random bitwise shares
        let r = rbg.take_one(ctx.narrow(&Step::GenerateRandomBits)).await?;

        // Step 3, 4. Reveal c = [a - b]_p
        let c = ctx
            .narrow(&Step::RevealAMinusB)
            .reveal(record_id, &(a_p.clone() - &r.b_p))
            .await?;
        let c_b = local_secret_shared_bits(&ctx, c.as_u128());

        // Step 5. Add back [b] bitwise. [d]_B = BitwiseSum(c, [b]_B) where d ∈ Z
        //
        // `BitwiseSum` outputs `l + 1` bits, so [d]_B is (l + 1)-bit long.
        let d_b = bitwise_sum(ctx.narrow(&Step::AddBtoC), record_id, &c_b, &r.b_b).await?;

        // Step 6. p <=? d. The paper says "p <? d", but should actually be "p <=? d"
        let q_p = BitwiseLessThanPrime::greater_than_or_equal_to_prime(
            ctx.narrow(&Step::IsPLessThanD),
            record_id,
            &d_b,
        )
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
        let h_b = bitwise_sum(ctx.narrow(&Step::AddDtoG), record_id, &d_b, &g_b).await?;

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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::BitDecomposition;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, Int},
        protocol::{boolean::random_bits_generator::RandomBitsGenerator, QueryId, RecordId},
        test_fixture::{bits_to_value, Reconstruct, Runner, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};

    async fn bit_decomposition<F>(world: &TestWorld, a: F) -> Vec<F>
    where
        F: Field + Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest(a, |ctx, a_p| async move {
                let rbg = RandomBitsGenerator::new();

                BitDecomposition::execute(ctx, RecordId::from(0), rbg, &a_p)
                    .await
                    .unwrap()
            })
            .await;

        // bit-decomposed values must have the same bit length of the target field
        assert_eq!(F::Integer::BITS as usize, result[0].len());
        assert_eq!(F::Integer::BITS as usize, result[1].len());
        assert_eq!(F::Integer::BITS as usize, result[2].len());

        result.reconstruct()
    }

    // 0.8 secs * 5 cases = 4 secs
    // New BitwiseLessThan -> 0.56 secs * 5 cases = 2.8
    #[tokio::test]
    pub async fn fp31() {
        let world = TestWorld::new(QueryId);
        let c = Fp31::from;
        assert_eq!(0, bits_to_value(&bit_decomposition(&world, c(0_u32)).await));
        assert_eq!(1, bits_to_value(&bit_decomposition(&world, c(1)).await));
        assert_eq!(15, bits_to_value(&bit_decomposition(&world, c(15)).await));
        assert_eq!(16, bits_to_value(&bit_decomposition(&world, c(16)).await));
        assert_eq!(30, bits_to_value(&bit_decomposition(&world, c(30)).await));
    }

    // This test takes more than 15 secs... I'm disabling it for now until
    // we optimize and/or find a way to make tests run faster.
    #[ignore]
    #[tokio::test]
    pub async fn fp32_bit_prime() {
        let world = TestWorld::new(QueryId);
        let c = Fp32BitPrime::from;
        let u16_max: u32 = u16::MAX.into();
        assert_eq!(0, bits_to_value(&bit_decomposition(&world, c(0_u32)).await));
        assert_eq!(1, bits_to_value(&bit_decomposition(&world, c(1)).await));
        assert_eq!(
            u128::from(u16_max),
            bits_to_value(&bit_decomposition(&world, c(u16_max)).await)
        );
        assert_eq!(
            u128::from(u16_max + 1),
            bits_to_value(&bit_decomposition(&world, c(u16_max + 1)).await)
        );
        assert_eq!(
            u128::from(Fp32BitPrime::PRIME - 1),
            bits_to_value(&bit_decomposition(&world, c(Fp32BitPrime::PRIME - 1)).await)
        );
    }
}
