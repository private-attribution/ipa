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
    protocol::{context::Context, BasicProtocols, RecordId},
    repeat64str,
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
    ///
    /// ## Panics
    /// Panics if g is empty, needs to be refactored.
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
        //  actually don't want this because it would be a different than expected number of multiplications.
        // if c == F::ZERO {
        //     return Ok(r.b_b);
        // }
        let c_int: u128 = c.as_u128();

        // Step 3. Compute [q]_p = 1 - [r_B < p - c ]_p. q is 1 iff r + c >= p in the integers.
        let p_minus_c: u128 = F::PRIME.into() - c.as_u128();
        let q_p = S::share_known_value(&ctx, F::ONE)
            - &bitwise_less_than_constant(
                ctx.narrow(&Step::IsRLessThanPMinusC),
                record_id,
                &r.b_b,
                p_minus_c,
            )
            .await?;

        // Step 4 has a lot going on. We'd going to break it down into substeps.
        // Step 4.1. Make a bitwise scalar value of f = 2^el + c - p.
        // let el = usize::try_from(u128::BITS - F::PRIME.into().leading_zeros()).unwrap();
        let el = u128::BITS - F::PRIME.into().leading_zeros();
        let two_exp_el = u128::pow(2, el);
        let f_int: u128 = two_exp_el + c.as_u128() - F::PRIME.into();
        debug_assert!(el <= 64);

        // Step 4.2. Compute [g]_B = (f_i - c_i) [q]_p + c_i
        let g_b = GBIterator::new(f_int, c_int);

        // and Step 5. Compute BitwiseSum([r]_B, [g]_B])
        let mut h: Vec<S> =
            compute_bit_addition(ctx.narrow(&Step::AddGtoR), record_id, r.b_b, g_b, &q_p).await?;

        // Step 6. h = a + 2^el, so we need all but the most significant bit of h,
        // so we need to drop the last bit. we could just not push the last value
        // in compute_bit_addition, but if we do that, it might as well not be a
        // different function...
        h.remove(h.len() - 1);
        Ok(h)
    }
}

async fn compute_bit_addition<'a, F, S, C, I>(
    ctx: C,
    record_id: RecordId,
    r_b: Vec<S>,
    g_b: I,
    q_p: &S,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    C: Context + RandomBits<F, Share = S>,
    I: Iterator<Item = G>,
{
    let el_usize = usize::try_from(u128::BITS - F::PRIME.into().leading_zeros()).unwrap();
    let mut h: Vec<S> = Vec::with_capacity(el_usize + 1);
    let mut last_carry_known_to_be_zero = true;
    let mut last_carry = S::ZERO;
    let one_minus_q_p = S::share_known_value(&ctx, F::ONE) - q_p;

    // an easier way to do this would simply be to have the g_b iterator
    // directly return either one of
    //    (q_p, one_minus_q_p, S::share_known_value(&ctx, F::ONE), or S::ZERO)
    // We have to "fake" multiplications so that there is a fixed number known
    // at compile time, so changing the g_b iterator wouldn't change the number
    // of multipliations.
    // It's unclear if the "fake" multiplications offer any benefit as is
    // or if they could be elimated in the future. If they can, we should
    // keep this structure, despite the addtional complexity, so that we can
    // benefit from it when they are elimiated. If not, we should simpliy further
    // and refactor with g_b directly returning a share S.

    for (bit_index, (bit, g_i)) in r_b.iter().zip(g_b).enumerate() {
        let mult_result = if last_carry_known_to_be_zero {
            // fake multiplication so that there is a fixed number of them
            S::ZERO
                .multiply(
                    &S::ZERO,
                    ctx.narrow(&BitAdditionStep::MultiplyStep(bit_index)),
                    record_id,
                ) // this is stupid
                .await?;

            S::ZERO
        } else {
            last_carry
                .multiply(
                    bit,
                    ctx.narrow(&BitAdditionStep::MultiplyStep(bit_index)),
                    record_id,
                )
                .await?
        };
        let last_carry_or_bit = -mult_result.clone() + &last_carry + bit;
        let next_carry = match g_i {
            G::Zero => {
                // fake multiplication so that there is a fixed number of them
                S::ZERO
                    .multiply(
                        &S::ZERO,
                        ctx.narrow(&BitAdditionStep::CarryStep(bit_index)),
                        record_id,
                    ) // this is stupid
                    .await?;
                mult_result
            }
            G::One => {
                // fake multiplication so that there is a fixed number of them
                S::ZERO
                    .multiply(
                        &S::ZERO,
                        ctx.narrow(&BitAdditionStep::CarryStep(bit_index)),
                        record_id,
                    ) // this is stupid
                    .await?;

                last_carry_known_to_be_zero = false;
                last_carry_or_bit
            }
            G::Q => {
                last_carry_known_to_be_zero = false;
                q_p.multiply(
                    &last_carry_or_bit,
                    // hack since we have two bit steps
                    ctx.narrow(&BitAdditionStep::CarryStep(bit_index)),
                    record_id,
                )
                .await?
            }
            G::NotQ => {
                last_carry_known_to_be_zero = false;
                one_minus_q_p
                    .multiply(
                        &last_carry_or_bit,
                        // hack since we have two bit steps
                        ctx.narrow(&BitAdditionStep::CarryStep(bit_index)),
                        record_id,
                    )
                    .await?
            }
        };
        // Each bit of the result can be computed very simply. It's just:
        // the current bit of `g` + the current bit of `r` + the carry from the previous bit `-2*next_carry`

        let constant_value = -next_carry.clone() * F::truncate_from(2_u128) + bit + &last_carry;
        let result_bit = match g_i {
            G::Zero => constant_value,
            G::One => S::share_known_value(&ctx, F::ONE) + &constant_value,
            G::Q => q_p.clone() + &constant_value,
            G::NotQ => constant_value + &one_minus_q_p,
        };
        h.push(result_bit);
        last_carry = next_carry;
    }
    h.push(last_carry);
    Ok(h)
}

struct GBIterator {
    f: u128,
    c: u128,
    bit_index: usize,
}

impl GBIterator {
    fn new(f: u128, c: u128) -> Self {
        GBIterator { f, c, bit_index: 0 }
    }
}

impl Iterator for GBIterator {
    type Item = G;

    fn next(&mut self) -> Option<Self::Item> {
        if self.bit_index < 128 {
            // g_i can either be c_i (known to be either 0, 1), or either [q]_p, ¬[q]_p
            // using an enum here because we're going to do something cleaver in bitwise add
            let f_i: bool = (self.f >> self.bit_index) & 1 == 1;
            let c_i: bool = (self.c >> self.bit_index) & 1 == 1;
            self.bit_index += 1;
            match (f_i, c_i) {
                // Case where f_i - c_i == 0
                (false, false) | (true, true) => {
                    if c_i {
                        return Some(G::One);
                    }
                    return Some(G::Zero);
                }
                // Case where f_i - c_i = 1
                (true, false) => return Some(G::Q),
                // Case where f_i - c_i = -1
                (false, true) => return Some(G::NotQ),
                // this is what g_i should actually be here, so we can use this down the road
                // let g_i_foo = S::share_known_value(&ctx, F::ONE) - &q_p.clone();
            }
        }
        None
    }
}

#[derive(Debug, PartialEq, Copy, Clone)]
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
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::RevealAMinusB => "reveal_a_minus_b",
            Self::IsRLessThanPMinusC => "is_r_less_than_p_minus_c",
            Self::AddGtoR => "add_g_to_r",
        }
    }
}

#[derive(Debug, Copy, Clone)]
pub enum BitAdditionStep {
    MultiplyStep(usize),
    CarryStep(usize),
}

impl crate::protocol::step::Step for BitAdditionStep {}

impl AsRef<str> for BitAdditionStep {
    fn as_ref(&self) -> &str {
        match self {
            BitAdditionStep::MultiplyStep(v) => {
                const BIT_OP: [&str; 64] = repeat64str!["multiply_bit"];
                BIT_OP[*v]
            }
            BitAdditionStep::CarryStep(v) => {
                const BIT_OP: [&str; 64] = repeat64str!["carry_bit"];
                BIT_OP[*v]
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use super::{compute_bit_addition, BitDecomposition, GBIterator, G};
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
        test_fixture::{bits_to_value, get_bits, Reconstruct, Runner, TestWorld, TestWorldConfig},
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

    async fn bit_addition<F>(
        world: &TestWorld,
        r: u32,
        g_b_vec: Vec<G>,
        q: F,
        num_bits: u32,
    ) -> Vec<F>
    where
        F: PrimeField + ExtendableField + Sized,
        Standard: Distribution<F>,
    {
        let r_f_b = get_bits::<F>(r, num_bits);

        let result = world
            .semi_honest((q, r_f_b), |ctx, (q_p, r_b_d)| {
                let g_b = &g_b_vec;
                async move {
                    let ctx = ctx.set_total_records(1);
                    let r_b = r_b_d.to_vec();
                    compute_bit_addition(ctx, RecordId::from(0), r_b, g_b.iter().copied(), &q_p)
                        .await
                        .unwrap()
                }
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

    #[tokio::test]
    pub async fn g_b_iterator() {
        // f: 0...0101 = 5
        // c: 0...0011 = 3
        let f: u128 = 5;
        let c: u128 = 3;
        let g_b = GBIterator::new(f, c);
        for (bit_index, g_i) in g_b.enumerate().take(4) {
            match bit_index {
                // (f_i - c_i) [q]_p + c_i
                0 => {
                    // f_i = 1, c_i = 1
                    assert_eq!(g_i, G::One);
                }
                1 => {
                    // f_i = 0, c_i = 1
                    assert_eq!(g_i, G::NotQ);
                }
                2 => {
                    // f_i = 1, c_i = 0
                    assert_eq!(g_i, G::Q);
                }
                3 => {
                    // f_i = 0, c_i = 0
                    assert_eq!(g_i, G::Zero);
                }
                _ => {
                    unreachable!()
                }
            }
        }
    }
}
