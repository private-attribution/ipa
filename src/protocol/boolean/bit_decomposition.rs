use super::{
    add_constant::{add_constant, maybe_add_constant_mod2l},
    bitwise_less_than_prime::BitwiseLessThanPrime,
    comparison::bitwise_less_than_constant,
    random_bits_generator::RandomBitsGenerator,
    RandomBits,
};
use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{context::Context, step::BitOpStep, BasicProtocols, RecordId},
    secret_sharing::Linear as LinearSecretSharing,
};

/// This is an implementation of "5. Simplified Bit-Decomposition Protocol" from T. Nishide and K. Ohta
///
/// It takes an input `[a] ∈ F_p` and outputs its bitwise additive share
/// `[a]_B = ([a]_0,...,[a]_l-1)` where `[a]_i ∈ F_p`.
///
/// 5. Simplified Bit-Decomposition Protocol
/// "Multiparty Computation for Interval, Equality, and Comparison without Bit-Decomposition Protocol"
/// Takashi Nishide and Kazuo Ohta
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
        rbg: &RandomBitsGenerator<F, S, C>,
        a_p: &S,
    ) -> Result<Vec<S>, Error>
    where
        F: PrimeField,
        S: LinearSecretSharing<F> + BasicProtocols<C, F>,
        C: Context + RandomBits<F, Share = S>,
    {
        // Step 1. Generate random bitwise shares [r]_B and linear share [r]_p
        let r = rbg.generate(record_id).await?;

        // Step 2: Reveal c = [a - r]_p
        let c = (a_p.clone() - &r.b_p)
            .reveal(ctx.narrow(&Step::RevealAMinusB), record_id)
            .await?;

        // Step 2.1: Edge case, if r is coincidentally a bit decomposition of [a]_p, we're done.
        if c == F::ZERO {
            return Ok(r.b_b);
        }

        // Step 3. Compute [q]_p = 1 - [r <_B p - c ]_p. q is 1 iff r + c >= p in the integers.
        let p_minus_c = F::PRIME - c;
        let q_p = bitwise_less_than_constant(
            ctx.narrow(&Step::IsRLessThanPMinusC),
            record_id,
            &r.b_b,
            p_minus_c.into(),
        )
        .await?;

        // Step 4 has a lot going on. We'd going to break it down into substeps.
        // Step 4.1. Make a bitwise scalar value of f = 2^el + c - p.
        let el = usize::try_from(u128::BITS - F::PRIME.into().leading_zeros()).unwrap();
        let two_exp_el = u128::pow(2, el.try_into().unwrap());
        let f_int: u128 = two_exp_el + c.into() - F::PRIME.into();

        // Step 4.2. Compute [g]_B = (f_i - c_i) [q]_p + c_i
        let mut g_B = Vec::with_capacity(el + 1);
        for bit_index in 0..el {
            let f_i: u128 = (f_int >> bit_index) & 1;
            let c_i: u128 = (c.into() >> bit_index) & 1;
            let f_i_minus_c_i: u128 = f_i - c_i;
            let g_prime: F = q_p.clone().into() * f_i_minus_c_i;
            g_B.push(g_prime + c_i.into())
        }

        // Step 5. Compute BitwiseSum([r]_B, [g]_B)
        // todo
        // Ok(h);

        // // Step 5. Add back [b] bitwise. [d]_B = BitwiseSum(c, [b]_B) where d ∈ Z
        // //
        // // `BitwiseSum` outputs one more bit than its input, so [d]_B is (el + 1)-bit long.
        // let d_b = add_constant(ctx.narrow(&Step::AddBtoC), record_id, &r.b_b, c.as_u128()).await?;

        // // Step 6. q = d >=? p (note: the paper uses p <? d, which is incorrect)
        // let q_p = BitwiseLessThanPrime::greater_than_or_equal_to_prime(
        //     ctx.narrow(&Step::IsPLessThanD),
        //     record_id,
        //     &d_b,
        // )
        // .await?;

        // // Step 7. a bitwise scalar value `f_B = bits(2^el - p)`
        // let el = u128::BITS - F::PRIME.into().leading_zeros();
        // let x = (1 << el) - F::PRIME.into();

        // // Step 8, 9. [g_i] = [q] * f_i
        // // Step 10. [h]_B = [d + g]_B, where [h]_B = ([h]_0,...[h]_(el+1))
        // // Step 11. [a]_B = ([h]_0,...[h]_(el-1))
        // let a_b =
        //     maybe_add_constant_mod2l(ctx.narrow(&Step::AddDtoG), record_id, &d_b, x, &q_p).await?;

        // Ok(a_b)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    RevealAMinusB,
    AddBtoC,
    IsPLessThanD,
    AddDtoG,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RevealAMinusB => "reveal_a_minus_b",
            Self::AddBtoC => "add_b_to_c",
            Self::IsPLessThanD => "is_p_less_than_d",
            Self::AddDtoG => "add_d_to_g",
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::BitDecomposition;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, PrimeField},
        protocol::{
            boolean::random_bits_generator::RandomBitsGenerator, context::Context, RecordId,
        },
        secret_sharing::replicated::malicious::ExtendableField,
        telemetry::{
            metrics::{
                BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED,
            },
            stats::Metrics,
        },
        test_fixture::{bits_to_value, Reconstruct, Runner, TestWorld, TestWorldConfig},
    };
    use bitvec::macros::internal::funty::Fundamental;
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    async fn bit_decomposition<F>(world: &TestWorld, a: F) -> Vec<F>
    where
        F: PrimeField + ExtendableField + Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest(a, |ctx, a_p| async move {
                let ctx = ctx.set_total_records(1);
                let rbg = RandomBitsGenerator::new(ctx.narrow("generate_random_bits"));
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

    /// Metrics that reflect IPA performance
    #[derive(Debug, Eq, PartialEq, Ord, PartialOrd)]
    struct PerfMetrics {
        /// Expected number of records sent between all helpers.
        records_sent: u64,
        /// Same as above, but bytes.
        bytes_sent: u64,
        /// Indexed random values generated by all helpers.
        indexed_prss: u64,
        /// Random values produced by PRSS random generators.
        seq_prss: u64,
    }

    impl PerfMetrics {
        pub fn from_snapshot(snapshot: &Metrics) -> Self {
            Self {
                records_sent: snapshot.get_counter(RECORDS_SENT),
                bytes_sent: snapshot.get_counter(BYTES_SENT),
                indexed_prss: snapshot.get_counter(INDEXED_PRSS_GENERATED),
                seq_prss: snapshot.get_counter(SEQUENTIAL_PRSS_GENERATED),
            }
        }
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

    #[tokio::test]
    async fn bit_decomposition_perf() {
        let test_config = TestWorldConfig::default().enable_metrics().with_seed(0);
        let world = TestWorld::new_with(test_config);
        let c = Fp31::truncate_from;
        let expected = PerfMetrics {
            records_sent: 1560,
            bytes_sent: 1560,
            indexed_prss: 1830,
            seq_prss: 0,
        };
        for _ in 0..20 {
            let max = Fp31::PRIME.as_u32();
            let x = rand::thread_rng().gen_range(0..=max - 1) as u128;
            assert_eq!(x, bits_to_value(&bit_decomposition(&world, c(x)).await));
        }
        let actual = PerfMetrics::from_snapshot(&world.metrics_snapshot());
        assert!(
            expected >= actual,
            "Bit Decomposition performance has degraded. Expected: {expected:?} >= {actual:?}"
        );
        if expected > actual {
            tracing::warn!("Baseline for Bit Decomposition has improved! Expected {expected:?}, got {actual:?}. \
            Strongly consider adjusting the baseline, so the gains won't be accidentally offset by a regression.");
        }
        println!("{:?}", actual);
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
