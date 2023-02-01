use super::into_bits;
use super::or::or;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;

/// Compares the `[a]` and `c`, and returns `1` iff `a > c`
///
/// Rabbit: Efficient Comparison for Secure Multi-Party Computation
/// 2.1 Comparison with Bitwise Shared Input – `LTBits` Protocol
/// Eleftheria Makri, et al.
/// <https://eprint.iacr.org/2021/119.pdf>
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn bitwise_greater_than_constant<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    c: F,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let c_bits = into_bits(c);
    let first_diff_bit = first_differing_bit(&ctx, record_id, a, &c_bits).await?;

    // Compute the dot-product [a] x `first_diff_bit`. 1 iff a > c.
    // We can swap `a` with `c` to yield 1 iff a < c. We just need to convert
    // `c` to `&[c]` using `local_secret_shared_bits`.
    ctx.narrow(&Step::DotProduct)
        .sum_of_products(record_id, &first_diff_bit, a)
        .await
}

async fn first_differing_bit<F, C, S>(
    ctx: &C,
    record_id: RecordId,
    a: &[S],
    b: &[F],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    let one = ctx.share_of_one();

    // Compute `[a] ^ b`. This step gives us the bits of values where they differ.
    let mut xored_bits = std::iter::zip(a, b)
        .map(|(a_bit, b_bit)| {
            // Local XOR operation `S ^ F`:
            //    [a] ^ b
            //  = a_1 - (2 * a_1 * b) + a_2 - (2 * a_2 * b) + a_3 - (2 * a_3 * b) + b
            //
            // There's `+ b` at the end, but we don't have Add ops impl for `S + F`.
            // We need to do a little trick here.
            //
            // If `b` = 1, then `+ 3` which is 1 in Fp2.
            // If `b` = 0, then `+ 0`.
            //
            // This is the same as adding a local share `[b] = b == 1 ? one : zero`.
            // Now we have `S + S` and computed `S ^ F` locally.
            let v = a_bit.clone() - &(a_bit.clone() * *b_bit * F::from(2));
            let b_share = if b_bit.as_u128() == 1 {
                one.clone()
            } else {
                S::ZERO
            };
            v + &b_share
        })
        .collect::<Vec<_>>();

    // In the next step, we'll compute prefix-or from MSB to LSB. Reverse the bits order.
    xored_bits.reverse();

    // Compute prefix-or of the xor'ed bits. This yields 0's followed by 1's with the transition
    // from 0 to 1 occurring at the index of the first different bit.
    let prefix_or_context = ctx.narrow(&Step::PrefixOr);
    let mut prefix_or = Vec::with_capacity(xored_bits.len());
    prefix_or.push(xored_bits[0].clone());
    for i in 1..xored_bits.len() {
        let result = or(
            prefix_or_context.narrow(&BitOpStep::from(i)),
            record_id,
            &prefix_or[i - 1],
            &xored_bits[i],
        )
        .await?;
        prefix_or.push(result);
    }
    // Change the order back to the little-endian format.
    prefix_or.reverse();

    // Subtract neighboring bits to yield all 0's and a single 1 at the index of the first
    // differing bit. Note that at the index where the transition from 0 to 1 happens,
    // `prefix_or[i + 1] > prefix_or[i]`. Do not change the order of the subtraction unless
    // we use Fp2, or the result will be `[p-1]`.
    let mut first_diff_bit = Vec::with_capacity(prefix_or.len());
    for i in 0..(prefix_or.len() - 1) {
        first_diff_bit.push(prefix_or[i].clone() - &prefix_or[i + 1]);
    }
    first_diff_bit.push(prefix_or[prefix_or.len() - 1].clone());

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
    use crate::ff::{Field, Fp31, Fp32BitPrime};
    use crate::protocol::boolean::into_bits;
    use crate::protocol::context::Context;
    use crate::protocol::RecordId;
    use crate::rand::thread_rng;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use proptest::prelude::Rng;
    use rand::{distributions::Standard, prelude::Distribution};

    async fn bitwise_gt<F: Field>(world: &TestWorld, a: F, b: F) -> F
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

        assert_eq!(zero, bitwise_gt(&world, zero, one).await);
        assert_eq!(one, bitwise_gt(&world, one, zero).await);
        assert_eq!(zero, bitwise_gt(&world, zero, zero).await);
        assert_eq!(zero, bitwise_gt(&world, one, one).await);

        assert_eq!(zero, bitwise_gt(&world, c(3_u8), c(7)).await);
        assert_eq!(one, bitwise_gt(&world, c(21), c(20)).await);
        assert_eq!(zero, bitwise_gt(&world, c(9), c(9)).await);

        assert_eq!(zero, bitwise_gt(&world, zero, c(Fp31::PRIME)).await);
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() {
        let c = Fp32BitPrime::from;
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;
        let u16_max: u32 = u16::MAX.into();
        let world = TestWorld::new().await;

        assert_eq!(zero, bitwise_gt(&world, zero, one).await);
        assert_eq!(one, bitwise_gt(&world, one, zero).await);
        assert_eq!(zero, bitwise_gt(&world, zero, zero).await);
        assert_eq!(zero, bitwise_gt(&world, one, one).await);

        assert_eq!(zero, bitwise_gt(&world, c(3_u32), c(7)).await);
        assert_eq!(one, bitwise_gt(&world, c(21), c(20)).await);
        assert_eq!(zero, bitwise_gt(&world, c(9), c(9)).await);

        assert_eq!(zero, bitwise_gt(&world, c(u16_max), c(u16_max + 1)).await);
        assert_eq!(one, bitwise_gt(&world, c(u16_max + 1), c(u16_max)).await);
        assert_eq!(
            zero,
            bitwise_gt(&world, c(u16_max), c(Fp32BitPrime::PRIME - 1)).await
        );
        assert_eq!(
            one,
            bitwise_gt(&world, c(Fp32BitPrime::PRIME - 1), c(u16_max)).await
        );

        assert_eq!(zero, bitwise_gt(&world, zero, c(Fp32BitPrime::PRIME)).await);
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
                bitwise_gt(&world, a, b).await
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
                    bitwise_gt(&world, Fp31::from(a), Fp31::from(b)).await
                );
            }
        }
    }
}
