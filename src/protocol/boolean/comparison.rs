use super::or::or;
use crate::{
    error::Error,
    ff::PrimeField,
    protocol::{
        boolean::{random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, BitOpStep, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};

// Compare an arithmetic-shared value `a` to a known value `c`.
//
// The known value must be a valid field element, i.e., `0 ≤ c < p`.
//
// Adapted from 6.1 Interval Test Protocol in "Multiparty Computation for Interval, Equality, and
// Comparison Without Bit-Decomposition Protocol", Nishide & Ohta, PKC 2007.
// <https://doi.org/10.1007/978-3-540-71677-8_23>
//
// The version in the paper tests c_1 < a < c_2. For us, c_1 is zero (which eliminates the `c < c_1`
// case enumerated in the paper), we test ≤ rather than <, and we finally return `a > c_2` which is
// ~(0 ≤ a ≤ c_2).
//
// The remainder of this description names the variables consistently with other routines in this
// file, which map to the paper as follows:
//
// Paper  Ours
// a      a
// r      r
// c      b
// c_1    0
// c_2    c
//
// Goal: Compute `a > c` as `~(0 ≤ a ≤ c)`
//
// Strategy:
//  1. Generate random r
//  2. Reveal b = a + r
//  3. Derive bounds r_low and r_high from public values, such that the desired result is a simple
//     function of `r_low < r` and `r < r_high`.
//
// Case 1: b > c
// b - c - 1 < r < b + 1
//  ⟺  b - c ≤ r ≤ b
//  ⟺  b - b ≤ b - r ≤ b - (b - c)
//  ⟺  0 ≤ a ≤ c
//  ⟺  ~(a > c)
//
// Case 2: b ≤ c
//  b < r < b + p - c
//  ⟺  b - (b + p - c) < b - r < b - b
//  ⟺  -(p - c) < a < 0
//  ⟺  a > c
//
/// # Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
///
/// # Panics
/// If `c` is not less than `F::PRIME`.
pub async fn greater_than_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    rbg: &RandomBitsGenerator<F, S, C>,
    a: &S,
    c: u128,
) -> Result<S, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    use GreaterThanConstantStep as Step;

    assert!(c < F::PRIME.into());

    let r = rbg.generate(record_id).await?;

    // Mask `a` with random `r` and reveal.
    let b = (r.b_p.clone() + a)
        .reveal(ctx.narrow(&Step::Reveal), record_id)
        .await?;

    let RBounds { r_lo, r_hi, invert } = compute_r_bounds(b.as_u128(), c, F::PRIME.into());

    // Following logic should match RBounds::evaluate
    let r_gt_r_lo =
        bitwise_greater_than_constant(ctx.narrow(&Step::CompareLo), record_id, &r.b_b, r_lo)
            .await?;
    let r_lt_r_hi =
        bitwise_less_than_constant(ctx.narrow(&Step::CompareHi), record_id, &r.b_b, r_hi).await?;

    // in_range = (r > r_lo) && (r < r_hi)
    let in_range = r_gt_r_lo
        .multiply(&r_lt_r_hi, ctx.narrow(&Step::And), record_id)
        .await?;

    // result = invert ? ~in_range : in_range
    if invert {
        Ok(S::share_known_value(&ctx, F::ONE) - &in_range)
    } else {
        Ok(in_range)
    }
}

struct RBounds {
    r_lo: u128,
    r_hi: u128,
    invert: bool,
}

#[cfg(all(test, not(feature = "shuttle")))]
impl RBounds {
    // This is used for the proptest. It must match the actual implementation!
    fn evaluate(&self, r: u128) -> bool {
        if self.invert {
            !(self.r_lo < r && r < self.r_hi)
        } else {
            self.r_lo < r && r < self.r_hi
        }
    }
}

fn compute_r_bounds(b: u128, c: u128, p: u128) -> RBounds {
    let r_lo;
    let r_hi;
    let invert;
    if b > c {
        // Case 1 in description of greater_than_constant
        r_lo = b - c - 1;
        r_hi = b + 1;
        invert = true;
    } else {
        // Case 2 in description of greater_than_constant
        r_lo = b;
        r_hi = p + b - c;
        invert = false;
    }
    RBounds { r_lo, r_hi, invert }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GreaterThanConstantStep {
    Reveal,
    CompareLo,
    CompareHi,
    And,
}

impl crate::protocol::Substep for GreaterThanConstantStep {}

impl AsRef<str> for GreaterThanConstantStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::Reveal => "reveal",
            Self::CompareLo => "compare_lo",
            Self::CompareHi => "compare_hi",
            Self::And => "and",
        }
    }
}

/// Compares the `[a]` and `c`, and returns `1` iff `a > c`
///
/// Rabbit: Efficient Comparison for Secure Multi-Party Computation
/// 2.1 Comparison with Bitwise Shared Input – `LTBits` Protocol
/// Eleftheria Makri, et al.
/// <https://eprint.iacr.org/2021/119.pdf>
///
/// # Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
///
/// # Panics
/// if bitwise share `a` is longer than 128 bits.
pub async fn bitwise_greater_than_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    c: u128,
) -> Result<S, Error>
where
    F: PrimeField,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    assert!(a.len() <= 128);

    let first_diff_bit = first_differing_bit(&ctx, record_id, a, c).await?;

    // Compute the dot-product [a] x `first_diff_bit`. 1 iff a > c.
    S::sum_of_products(ctx.narrow(&Step::DotProduct), record_id, &first_diff_bit, a).await
}

/// Compares the `[a]` and `c`, and returns `1` iff `a < c`
///
/// Rabbit: Efficient Comparison for Secure Multi-Party Computation
/// 2.1 Comparison with Bitwise Shared Input – `LTBits` Protocol
/// Eleftheria Makri, et al.
/// <https://eprint.iacr.org/2021/119.pdf>
///
/// # Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
///
/// # Panics
/// if bitwise share `a` is longer than 128 bits.
pub async fn bitwise_less_than_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    c: u128,
) -> Result<S, Error>
where
    F: PrimeField,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    assert!(a.len() <= 128);

    let first_diff_bit = first_differing_bit(&ctx, record_id, a, c).await?;

    let not_a = a
        .iter()
        .map(|bit| S::share_known_value(&ctx, F::ONE) - bit)
        .collect::<Vec<_>>();

    // Compute the dot-product [~a] x `first_diff_bit`. 1 iff a < c.
    S::sum_of_products(
        ctx.narrow(&Step::DotProduct),
        record_id,
        &first_diff_bit,
        &not_a,
    )
    .await
}

async fn first_differing_bit<F, C, S>(
    ctx: &C,
    record_id: RecordId,
    a: &[S],
    b: u128,
) -> Result<Vec<S>, Error>
where
    F: PrimeField,
    C: Context,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let one = S::share_known_value(ctx, F::ONE);

    // Compute `[a] ^ b`. This step gives us the bits of values where they differ.
    let xored_bits = a
        .iter()
        .enumerate()
        .map(|(i, a_bit)| {
            // Local XOR
            if ((b >> i) & 1) == 0 {
                a_bit.clone()
            } else {
                one.clone() - a_bit
            }
        })
        .collect::<Vec<_>>();

    // Compute prefix-or of the xor'ed bits. This yields 0's followed by 1's with the transition
    // from 0 to 1 occurring at the index of the first different bit.
    let prefix_or_context = ctx.narrow(&Step::PrefixOr);
    let mut first_diff_bit = Vec::with_capacity(xored_bits.len());
    let mut previous_bit = xored_bits.last().cloned().unwrap();
    first_diff_bit.push(previous_bit.clone());
    // Process from MSB to LSB
    for (i, bit) in xored_bits
        .iter()
        .take(xored_bits.len() - 1)
        .rev()
        .enumerate()
    {
        let result = or(
            prefix_or_context.narrow(&BitOpStep::from(i)),
            record_id,
            &previous_bit,
            bit,
        )
        .await?;

        // Subtract the previous or'ed bit to yield a single 1 at the index of the first
        // differing bit. Note that at the index where the transition from 0 to 1 happens,
        // `prefix_or[i + 1] > prefix_or[i]`. Do not change the order of the subtraction
        // unless we use Fp2, or the result will be `[p-1]`.
        first_diff_bit.push(result.clone() - &previous_bit);

        previous_bit = result;
    }
    // Change the order back to the little-endian format.
    first_diff_bit.reverse();

    Ok(first_diff_bit)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    PrefixOr,
    DotProduct,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::PrefixOr => "prefix_or",
            Self::DotProduct => "dot_product",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::{
        bitwise_greater_than_constant, bitwise_less_than_constant, compute_r_bounds,
        greater_than_constant,
    };
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, PrimeField},
        protocol::{
            boolean::random_bits_generator::RandomBitsGenerator, context::Context, RecordId,
        },
        rand::thread_rng,
        secret_sharing::SharedValue,
        test_fixture::{into_bits, Reconstruct, Runner, TestWorld},
    };
    use proptest::proptest;
    use rand::{distributions::Standard, prelude::Distribution, Rng};

    async fn bitwise_lt<F: PrimeField>(world: &TestWorld, a: F, b: u128) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let input = into_bits(a);

        let result = world
            .semi_honest(input.clone(), |ctx, a_share| async move {
                bitwise_less_than_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(input.clone(), |ctx, a_share| async move {
                bitwise_less_than_constant(ctx.set_total_records(1), RecordId::from(0), &a_share, b)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);

        result
    }

    async fn bitwise_gt<F: PrimeField>(world: &TestWorld, a: F, b: u128) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let input = into_bits(a);

        let result = world
            .semi_honest(input.clone(), |ctx, a_share| async move {
                bitwise_greater_than_constant(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    b,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(input.clone(), |ctx, a_share| async move {
                bitwise_greater_than_constant(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    b,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);

        result
    }

    async fn gt<F: PrimeField>(world: &TestWorld, lhs: F, rhs: u128) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest(lhs, |ctx, lhs| async move {
                greater_than_constant(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &RandomBitsGenerator::new(ctx, 1),
                    &lhs,
                    rhs,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(lhs, |ctx, lhs| async move {
                greater_than_constant(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &RandomBitsGenerator::new(ctx, 1),
                    &lhs,
                    rhs,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);

        result
    }

    #[tokio::test]
    pub async fn gt_fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::default();

        assert_eq!(zero, gt(&world, zero, 1).await);
        assert_eq!(one, gt(&world, one, 0).await);
        assert_eq!(zero, gt(&world, zero, 0).await);
        assert_eq!(zero, gt(&world, one, 1).await);

        assert_eq!(zero, gt(&world, c(3_u8), 7).await);
        assert_eq!(one, gt(&world, c(21), 20).await);
        assert_eq!(zero, gt(&world, c(9), 9).await);

        assert_eq!(zero, gt(&world, zero, u128::from(Fp31::PRIME) - 1).await);
    }

    #[tokio::test]
    pub async fn bw_gt_fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::default();

        assert_eq!(zero, bitwise_gt(&world, zero, 1).await);
        assert_eq!(one, bitwise_gt(&world, one, 0).await);
        assert_eq!(zero, bitwise_gt(&world, zero, 0).await);
        assert_eq!(zero, bitwise_gt(&world, one, 1).await);

        assert_eq!(zero, bitwise_gt(&world, c(3_u8), 7).await);
        assert_eq!(one, bitwise_gt(&world, c(21), 20).await);
        assert_eq!(zero, bitwise_gt(&world, c(9), 9).await);

        assert_eq!(zero, bitwise_gt(&world, zero, Fp31::PRIME.into()).await);
        assert_eq!(one, bitwise_gt(&world, c(Fp31::PRIME - 1), 0).await);
    }

    #[tokio::test]
    pub async fn bw_lt_fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::default();

        assert_eq!(one, bitwise_lt(&world, zero, 1).await);
        assert_eq!(zero, bitwise_lt(&world, one, 0).await);
        assert_eq!(zero, bitwise_lt(&world, zero, 0).await);
        assert_eq!(zero, bitwise_lt(&world, one, 1).await);

        assert_eq!(one, bitwise_lt(&world, c(3_u8), 7).await);
        assert_eq!(zero, bitwise_lt(&world, c(21), 20).await);
        assert_eq!(zero, bitwise_lt(&world, c(9), 9).await);

        assert_eq!(one, bitwise_lt(&world, zero, Fp31::PRIME.into()).await);
        assert_eq!(zero, bitwise_lt(&world, c(Fp31::PRIME - 1), 0).await);
    }

    #[tokio::test]
    pub async fn bw_gt_fp_32bit_prime() {
        let c = Fp32BitPrime::from;
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;
        let u16_max: u32 = u16::MAX.into();
        let world = TestWorld::default();

        assert_eq!(zero, bitwise_gt(&world, zero, 1).await);
        assert_eq!(one, bitwise_gt(&world, one, 0).await);
        assert_eq!(zero, bitwise_gt(&world, zero, 0).await);
        assert_eq!(zero, bitwise_gt(&world, one, 1).await);

        assert_eq!(zero, bitwise_gt(&world, c(3_u32), 7).await);
        assert_eq!(one, bitwise_gt(&world, c(21), 20).await);
        assert_eq!(zero, bitwise_gt(&world, c(9), 9).await);

        assert_eq!(
            zero,
            bitwise_gt(&world, c(u16_max), (u16_max + 1).into()).await
        );
        assert_eq!(
            one,
            bitwise_gt(&world, c(u16_max + 1), u16_max.into()).await
        );
        assert_eq!(
            zero,
            bitwise_gt(&world, c(u16_max), (Fp32BitPrime::PRIME - 1).into()).await
        );
        assert_eq!(
            one,
            bitwise_gt(&world, c(Fp32BitPrime::PRIME - 1), u16_max.into()).await
        );

        assert_eq!(
            zero,
            bitwise_gt(&world, zero, Fp32BitPrime::PRIME.into()).await
        );
    }

    proptest! {
        #[test]
        fn gt_fp31_proptest(a in 0..Fp31::PRIME, c in 0..Fp31::PRIME) {
            type F = Fp31;
            let r = thread_rng().gen::<F>();
            let b = F::from(a) + r;
            assert_eq!(a > c, compute_r_bounds(b.as_u128(), c.into(), F::PRIME.into()).evaluate(r.as_u128()));
        }

        #[test]
        fn gt_fp_32bit_prime_proptest(a in 0..Fp32BitPrime::PRIME, c in 0..Fp32BitPrime::PRIME) {
            type F = Fp32BitPrime;
            let r = thread_rng().gen::<F>();
            let b = F::from(a) + r;
            assert_eq!(a > c, compute_r_bounds(b.as_u128(), c.into(), F::PRIME.into()).evaluate(r.as_u128()));
        }
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn bw_cmp_random_32_bit_prime_field_elements() {
        let world = TestWorld::default();
        let mut rand = thread_rng();
        for _ in 0..1000 {
            let a = rand.gen::<Fp32BitPrime>();
            let b = rand.gen::<Fp32BitPrime>();
            assert_eq!(
                Fp32BitPrime::from(a.as_u128() > b.as_u128()),
                bitwise_gt(&world, a, b.as_u128()).await
            );
        }
    }

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn bw_cmp_all_fp31() {
        let world = TestWorld::default();
        for a in 0..Fp31::PRIME {
            for b in 0..Fp31::PRIME {
                assert_eq!(
                    Fp31::from(a > b),
                    bitwise_gt(&world, Fp31::from(a), b.into()).await
                );
            }
        }
    }
}
