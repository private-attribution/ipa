use super::or::or;
use crate::{
    error::Error,
    ff::Field,
    protocol::{
        boolean::{random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, BitOpStep, RecordId,
    },
    secret_sharing::Arithmetic as ArithmeticSecretSharing,
};

// Adapted from 6.1 Interval Test Protocol in "Multiparty Computation for Interval, Equality, and
// Comparison Without Bit-Decomposition Protocol", Nishide & Ohta, PKC 2007.
// <https://doi.org/10.1007/978-3-540-71677-8_23>
//
// The version in the paper tests c_1 < x < c_2. For us, c_1 is zero (which eliminates the `c < c_1`
// case enumerated in the paper), we test ≤ rather than <, and we finally return `x > c_2` which is
// ~(0 ≤ x ≤ c_2).
//
// The remainder of this description names the variables consistently with other routines in this
// file, which map to the paper as follows:
//
// Paper  Ours
// x      a
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
pub async fn greater_than_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    rbg: &RandomBitsGenerator<F, S, C>,
    a: &S,
    c: u128,
) -> Result<S, Error>
where
    F: Field,
    C: Context + RandomBits<F, Share = S>,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
{
    use GreaterThanConstantStep as Step;

    let r = rbg.generate().await?;

    let b = (r.b_p.clone() + a)
        .reveal(ctx.narrow(&Step::Reveal), record_id)
        .await?;

    let r_lo;
    let r_hi;
    let invert;
    if b.as_u128() > c {
        r_lo = b.as_u128() - c - 1;
        r_hi = b.as_u128() + 1;
        invert = true;
    } else {
        r_lo = b.as_u128();
        r_hi = F::PRIME.into() + b.as_u128() - c;
        invert = false;
    }

    let r_gt_r_lo =
        bitwise_greater_than_constant(ctx.narrow(&Step::CompareLo), record_id, &r.b_b, r_lo)
            .await?;
    let r_lt_r_hi =
        bitwise_less_than_constant(ctx.narrow(&Step::CompareHi), record_id, &r.b_b, r_hi).await?;

    let result = r_gt_r_lo
        .multiply(&r_lt_r_hi, ctx.narrow(&Step::Multiply), record_id)
        .await?;

    if invert {
        Ok(S::share_known_value(&ctx, F::ONE) - &result)
    } else {
        Ok(result)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum GreaterThanConstantStep {
    Reveal,
    CompareLo,
    CompareHi,
    Multiply,
}

impl crate::protocol::Substep for GreaterThanConstantStep {}

impl AsRef<str> for GreaterThanConstantStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::Reveal => "reveal",
            Self::CompareLo => "compare_lo",
            Self::CompareHi => "compare_hi",
            Self::Multiply => "multiply",
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
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
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
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
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
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
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
    use super::{bitwise_greater_than_constant, greater_than_constant};
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{
            boolean::random_bits_generator::RandomBitsGenerator, context::Context, RecordId,
        },
        rand::thread_rng,
        secret_sharing::SharedValue,
        test_fixture::{into_bits, Reconstruct, Runner, TestWorld},
    };
    use proptest::prelude::Rng;
    use rand::{distributions::Standard, prelude::Distribution};

    async fn bitwise_gt<F: Field>(world: &TestWorld, a: F, b: u128) -> F
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

    async fn gt<F: Field>(world: &TestWorld, lhs: F, rhs: u128) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest(lhs, |ctx, lhs| async move {
                greater_than_constant(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &RandomBitsGenerator::new(ctx),
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
                    &RandomBitsGenerator::new(ctx),
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
    pub async fn fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::new().await;

        assert_eq!(zero, gt(&world, zero, 1).await);
        assert_eq!(one, gt(&world, one, 0).await);
        assert_eq!(zero, gt(&world, zero, 0).await);
        assert_eq!(zero, gt(&world, one, 1).await);

        assert_eq!(zero, gt(&world, c(3_u8), 7).await);
        assert_eq!(one, gt(&world, c(21), 20).await);
        assert_eq!(zero, gt(&world, c(9), 9).await);

        assert_eq!(zero, gt(&world, zero, Fp31::PRIME.into()).await);
    }

    #[tokio::test]
    pub async fn bw_fp31() {
        let c = Fp31::from;
        let zero = Fp31::ZERO;
        let one = Fp31::ONE;
        let world = TestWorld::new().await;

        assert_eq!(zero, bitwise_gt(&world, zero, 1).await);
        assert_eq!(one, bitwise_gt(&world, one, 0).await);
        assert_eq!(zero, bitwise_gt(&world, zero, 0).await);
        assert_eq!(zero, bitwise_gt(&world, one, 1).await);

        assert_eq!(zero, bitwise_gt(&world, c(3_u8), 7).await);
        assert_eq!(one, bitwise_gt(&world, c(21), 20).await);
        assert_eq!(zero, bitwise_gt(&world, c(9), 9).await);

        assert_eq!(zero, bitwise_gt(&world, zero, Fp31::PRIME.into()).await);
    }

    #[tokio::test]
    pub async fn bw_fp_32bit_prime() {
        let c = Fp32BitPrime::from;
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;
        let u16_max: u32 = u16::MAX.into();
        let world = TestWorld::new().await;

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

    // this test is for manual execution only
    #[ignore]
    #[tokio::test]
    pub async fn bw_cmp_random_32_bit_prime_field_elements() {
        let world = TestWorld::new().await;
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
        let world = TestWorld::new().await;
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
