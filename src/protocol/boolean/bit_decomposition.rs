use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        boolean::{
            add_constant::{add_constant, maybe_add_constant_mod2l},
            bitwise_less_than_prime::BitwiseLessThanPrime,
            random_bits_generator::RandomBitsGenerator,
        },
        context::UpgradedContext,
        BasicProtocols, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};
use ipa_macros::step;
use strum::AsRefStr;

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
    pub async fn execute<F, C, S>(
        ctx: C,
        record_id: RecordId,
        rbg: &RandomBitsGenerator<F, C, S>,
        a_p: &S,
    ) -> Result<Vec<S>, Error>
    where
        F: PrimeField,
        C: UpgradedContext<F, Share = S>,
        S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    {
        // step 1 in the paper is just describing the input, `[a]_p` where `a ∈ F_p`

        // Step 2. Generate random bitwise shares
        let r = rbg.generate(record_id).await?;

        // Step 3, 4. Reveal c = [a - b]_p
        let c = (a_p.clone() - &r.b_p)
            .reveal(ctx.narrow(&Step::RevealAMinusB), record_id)
            .await?;

        // Step 5. Add back [b] bitwise. [d]_B = BitwiseSum(c, [b]_B) where d ∈ Z
        //
        // `BitwiseSum` outputs one more bit than its input, so [d]_B is (el + 1)-bit long.
        let d_b = add_constant(ctx.narrow(&Step::AddBtoC), record_id, &r.b_b, c.as_u128()).await?;

        // Step 6. q = d >=? p (note: the paper uses p <? d, which is incorrect)
        let q_p = BitwiseLessThanPrime::greater_than_or_equal_to_prime(
            ctx.narrow(&Step::IsPLessThanD),
            record_id,
            &d_b,
        )
        .await?;

        // Step 7. a bitwise scalar value `f_B = bits(2^el - p)`
        let el = u128::BITS - F::PRIME.into().leading_zeros();
        let x = (1 << el) - F::PRIME.into();

        // Step 8, 9. [g_i] = [q] * f_i
        // Step 10. [h]_B = [d + g]_B, where [h]_B = ([h]_0,...[h]_(el+1))
        // Step 11. [a]_B = ([h]_0,...[h]_(el-1))
        let a_b =
            maybe_add_constant_mod2l(ctx.narrow(&Step::AddDtoG), record_id, &d_b, x, &q_p).await?;

        Ok(a_b)
    }
}

#[step]
pub(crate) enum Step {
    RevealAMinusB,
    AddBtoC,
    IsPLessThanD,
    AddDtoG,
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::BitDecomposition;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, PrimeField},
        protocol::{
            boolean::random_bits_generator::RandomBitsGenerator,
            context::{Context, UpgradableContext, Validator},
            RecordId,
        },
        secret_sharing::replicated::malicious::ExtendableField,
        test_fixture::{bits_to_value, Reconstruct, Runner, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution};

    async fn bit_decomposition<F>(world: &TestWorld, a: F) -> Vec<F>
    where
        F: PrimeField + ExtendableField + Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest(a, |ctx, a_p| async move {
                let validator = ctx.validator();
                let ctx = validator.context().set_total_records(1);
                let rbg = RandomBitsGenerator::new(ctx.narrow("bitgen"));
                BitDecomposition::execute(ctx, RecordId::from(0), &rbg, &a_p)
                    .await
                    .unwrap()
            })
            .await;

        // bit-decomposed values generate valid number of bits to fit the target field values
        let l = u128::BITS - F::PRIME.into().leading_zeros();
        assert_eq!(usize::try_from(l).unwrap(), result[0].len());
        assert_eq!(usize::try_from(l).unwrap(), result[1].len());
        assert_eq!(usize::try_from(l).unwrap(), result[2].len());

        result.reconstruct()
    }

    // 0.8 secs * 5 cases = 4 secs
    // New BitwiseLessThan -> 0.56 secs * 5 cases = 2.8
    #[tokio::test]
    pub async fn fp31() {
        let world = TestWorld::default();
        let c = Fp31::truncate_from;
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
        let world = TestWorld::default();
        let c = Fp32BitPrime::truncate_from;
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
