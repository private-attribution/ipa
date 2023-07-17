use super::{
    // remove these
    // add_constant::{add_constant, maybe_add_constant_mod2l},
    // bitwise_less_than_prime::BitwiseLessThanPrime,
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
        let c: F = (a_p.clone() - &r.b_p)
            .reveal(ctx.narrow(&Step::RevealAMinusB), record_id)
            .await?;

        // Step 2.1: Edge case, if r is coincidentally a bit decomposition of [a]_p, we're done.
        if c == F::ZERO {
            return Ok(r.b_b);
        }

        // Step 3. Compute [q]_p = 1 - [r <_B p - c ]_p. q is 1 iff r + c >= p in the integers.
        let p_minus_c: u128 = F::PRIME.into() - c.as_u128();
        let q_p = bitwise_less_than_constant(
            ctx.narrow(&Step::IsRLessThanPMinusC),
            record_id,
            &r.b_b,
            p_minus_c.into(),
        )
        .await?;

        // Step 4 has a lot going on. We'd going to break it down into substeps.
        // Step 4.1. Make a bitwise scalar value of f = 2^el + c - p.
        // let el = usize::try_from(u128::BITS - F::PRIME.into().leading_zeros()).unwrap();
        let el = u128::BITS - F::PRIME.into().leading_zeros();
        let two_exp_el = u128::pow(2, el);
        let _f_int: u128 = two_exp_el + c.as_u128() - F::PRIME.into();
        debug_assert!(_f_int < u64::max_value().into());
        let f_int: u64 = _f_int as u64;

        // Step 4.2. Compute [g]_B = (f_i - c_i) [q]_p + c_i
        let mut g_bin: Vec<G> = Vec::with_capacity(usize::try_from(el).unwrap());
        for bit_index in 0..el {
            // these are single bits, so let's make them bools
            let f_i: bool = (f_int >> bit_index) & 1 == 1;
            let c_i: bool = (c.as_u128() >> bit_index) & 1 == 1;
            // g_i can either be c_i (known to be either 0, 1), or either [q]_p, ¬[q]_p
            // using an enum here because we're going to do something cleaver in bitwise add
            let g_i: G = match (f_i, c_i) {
                // Case where f_i - c_i == 0
                (false, false) | (true, true) => match c_i {
                    true => G::One,
                    false => G::Zero,
                },
                // Case where f_i - c_i = 1
                (true, false) => G::Q,
                // Case where f_i - c_i = -1
                (false, true) => G::NotQ,
                // this is what g_i should actually be here, so we can use this down the road
                // let g_i_foo = S::share_known_value(&ctx, F::ONE) - &q_p.clone();
            };
            g_bin.push(g_i);
            // let f_i_minus_c_i: u64 = f_i - c_i;
            // let g_prime: S = q_p.clone().into() * f_i_minus_c_i;
            // // c_i ∈ {0, 1}, so F::truncate_from will work
            // debug_assert!(c_i <= 1_u128);
            // g_bin.push(S::share_known_value(&ctx, F::truncate_from(c_i)) + &g_prime);
        }

        // Step 5. Compute BitwiseSum([r]_B, [g]_B)
        let mut h: Vec<S> = Vec::with_capacity(usize::try_from(el).unwrap());
        let one_minus_q_p = S::share_known_value(&ctx, F::ONE) - &q_p.clone();
        let (mut last_carry, result_bit, mut last_carry_known_to_be_zero) = match g_bin[0] {
            G::Zero => (S::ZERO, r.b_b[0].clone(), true),
            G::One => (r.b_b[0].clone(), S::share_known_value(&ctx, F::ONE), false),
            G::Q => (
                q_p.multiply(&r.b_b[0], ctx.narrow(&Step::AddGtoR), record_id)
                    .await?,
                q_p.clone() + &r.b_b[0],
                false,
            ),
            G::NotQ => (
                one_minus_q_p
                    .clone()
                    .multiply(&r.b_b[0], ctx.narrow(&Step::AddGtoR), record_id)
                    .await?,
                one_minus_q_p.clone() + &r.b_b[0],
                false,
            ),
        };
        h.push(result_bit);

        for (bit_index, bit) in r.b_b.iter().enumerate().skip(1) {
            let mult_result = if last_carry_known_to_be_zero {
                // TODO: this makes me sad
                S::ZERO
                    .multiply(&S::ZERO, ctx.narrow(&BitOpStep::from(bit_index)), record_id) // this is stupid
                    .await?;

                S::ZERO
            } else {
                last_carry
                    .multiply(bit, ctx.narrow(&BitOpStep::from(bit_index)), record_id)
                    .await?
            };
            let last_carry_or_bit = -mult_result.clone() + &last_carry + bit;
            let next_carry = match &g_bin[bit_index] {
                G::Zero => mult_result,
                G::One => {
                    last_carry_known_to_be_zero = false;
                    last_carry_or_bit
                }
                G::Q => {
                    last_carry_known_to_be_zero = false;
                    q_p.multiply(
                        &last_carry_or_bit,
                        // hack since we have two bit steps
                        ctx.narrow(&BitOpStep::from(usize::try_from(el).unwrap() + bit_index)),
                        record_id,
                    )
                    .await?
                }
                G::NotQ => {
                    last_carry_known_to_be_zero = false;
                    one_minus_q_p
                        .clone()
                        .multiply(
                            &last_carry_or_bit,
                            // hack since we have two bit steps
                            ctx.narrow(&BitOpStep::from(usize::try_from(el).unwrap() + bit_index)),
                            record_id,
                        )
                        .await?
                }
            };
            // Each bit of the result can be computed very simply. It's just:
            // the current bit of `g` + the current bit of `r` + the carry from the previous bit `-2*next_carry`

            let constant_value = -next_carry.clone() * F::truncate_from(2_u128) + bit + &last_carry;
            let result_bit = match &g_bin[bit_index] {
                G::Zero => constant_value,
                G::One => S::share_known_value(&ctx, F::ONE) + &constant_value,
                G::Q => q_p.clone() + &constant_value,
                G::NotQ => one_minus_q_p.clone() + &constant_value,
            };
            h.push(result_bit);

            last_carry = next_carry;
        }
        // Step 6. h = a + 2^el, so we need all but the most significant bit of h,
        //thus we omit the final h.push(last_carry).
        Ok(h)
    }
}

#[derive(Debug, PartialEq)]
enum G {
    Zero,
    One,
    Q,
    NotQ,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    RevealAMinusB,
    IsRLessThanPMinusC,
    AddGtoR,
    // todo remove these
    // AddBtoC,
    // IsPLessThanD,
    // AddDtoG,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RevealAMinusB => "reveal_a_minus_b",
            Self::IsRLessThanPMinusC => "is_r_less_than_p_minus_c",
            Self::AddGtoR => "add_g_to_r",
            // todo remove these
            // Self::AddBtoC => "add_b_to_c",
            // Self::IsPLessThanD => "is_p_less_than_d",
            // Self::AddDtoG => "add_d_to_g",
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
