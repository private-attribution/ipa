use super::or::or;
use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BasicProtocols, BitOpStep, RecordId},
    secret_sharing::Arithmetic as ArithmeticSecretSharing,
};

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
    // We can swap `a` with `c` to yield 1 iff a < c. We just need to convert
    // `c` to `&[c]` using `local_secret_shared_bits`.
    S::sum_of_products(ctx.narrow(&Step::DotProduct), record_id, &first_diff_bit, a).await
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
    use super::bitwise_greater_than_constant;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{context::Context, RecordId},
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

    #[tokio::test]
    pub async fn fp31() {
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
    pub async fn fp_32bit_prime() {
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
    pub async fn cmp_random_32_bit_prime_field_elements() {
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
    pub async fn cmp_all_fp31() {
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
