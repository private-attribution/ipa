use super::xor;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::Context, BitOpStep, RecordId};
use crate::secret_sharing::Arithmetic as ArithmeticSecretSharing;
use futures::future::{try_join, try_join_all};
use std::iter::zip;

/// This is an implementation of Bitwise Less-Than on bitwise-shared numbers.
///
/// `BitwiseLessThan` takes inputs `[a]_B = ([a_1]_p,...,[a_l]_p)` where
/// `a1,...,a_l ∈ {0,1} ⊆ F_p` and `[b]_B = ([b_1]_p,...,[b_l]_p)` where
/// `b1,...,b_l ∈ {0,1} ⊆ F_p`, then computes `h ∈ {0, 1} <- a <? b` where
/// `h = 1` iff `a` is less than `b`.
///
/// Note that `[a]_B` can be converted to `[a]_p` by `Σ (2^i * a_i), i=0..l`. In
/// other words, if comparing two integers, the protocol expects inputs to be in
/// the little-endian; the least-significant byte at the smallest address (0'th
/// element).
///
pub struct BitwiseLessThan {}

impl BitwiseLessThan {
    ///
    /// For each bit index, compare the corresponding bits of `a` and `b` and return `a_i != b_a`
    /// Logically, "is this bit of `a` different from this bit of `b`?"
    /// Results returned in *big-endian* order (most significant digit first)
    /// # Example
    /// ```ignore
    ///   [a] = 1 1 0 1 0 1 1 0
    ///   [b] = 1 1 0 0 1 0 0 1
    ///   =>    0 0 0 1 1 1 1 1
    /// ```
    async fn xor_all_but_lsb<F, C, S>(
        a: &[S],
        b: &[S],
        ctx: C,
        record_id: RecordId,
    ) -> Result<Vec<S>, Error>
    where
        F: Field,
        C: Context<F, Share = S>,
        S: ArithmeticSecretSharing<F>,
    {
        let xor = zip(a, b)
            .enumerate()
            .skip(1)
            .rev()
            .map(|(i, (a_bit, b_bit))| {
                let c = ctx.narrow(&BitOpStep::from(i));
                async move { xor(c, record_id, a_bit, b_bit).await }
            });
        try_join_all(xor).await
    }

    ///
    /// For each bit index, compare the corresponding bits of `a` and `b` and return `a_i == 0 && b_i == 1`
    /// Logically, "is this bit of `a` less than this bit of `b`?"
    /// Results returned in *big-endian* order (most significant digit first)
    /// # Example
    /// ```ignore
    ///   [a] = 1 1 0 1 0 1 1 0
    ///   [b] = 1 1 0 0 1 0 0 1
    ///   =>    0 0 0 0 1 0 0 1
    /// ```
    async fn less_than_all_bits<F, C, S>(
        a: &[S],
        b: &[S],
        ctx: C,
        record_id: RecordId,
    ) -> Result<Vec<S>, Error>
    where
        F: Field,
        C: Context<F, Share = S>,
        S: ArithmeticSecretSharing<F>,
    {
        let less_than = zip(a, b).enumerate().rev().map(|(i, (a_bit, b_bit))| {
            let c = ctx.narrow(&BitOpStep::from(i));
            let one = c.share_of_one();
            async move { c.multiply(record_id, &(one - a_bit), b_bit).await }
        });
        try_join_all(less_than).await
    }

    ///
    /// Compares the `a` and `b`, and returns `1` iff `a < b`
    /// This logic is very simple:
    /// Starting from the most-significant bit and working downwards:
    /// For the most-significant bit: check if `a_0 == 0 && b_0 == 1`
    /// For any the other bit `j`: check if `a_i == b_i` for `i = 0..j-1` AND `(a_j == 0 && b_j == 1)`
    /// Finally, since at most one of these conditions can be true, it is sufficient to just add up
    /// all of these conditions. That sum is logically equivalent to an OR of all conditions.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F, C, S>(ctx: C, record_id: RecordId, a: &[S], b: &[S]) -> Result<S, Error>
    where
        F: Field,
        C: Context<F, Share = S>,
        S: ArithmeticSecretSharing<F>,
    {
        debug_assert_eq!(a.len(), b.len());

        let (xored_bits, less_thaned_bits) = try_join(
            Self::xor_all_but_lsb(a, b, ctx.narrow(&Step::BitwiseAXorB), record_id),
            Self::less_than_all_bits(a, b, ctx.narrow(&Step::BitwiseALessThanB), record_id),
        )
        .await?;

        let one = ctx.share_of_one();
        let mut any_condition_met = less_thaned_bits[0].clone();
        let mut all_preceeding_bits_the_same = one.clone() - &(xored_bits[0]);
        let check_each_bit_context = ctx.narrow(&Step::CheckEachBit);
        let prefix_equal_context = ctx.narrow(&Step::PrefixEqual);
        for i in 1..(less_thaned_bits.len() - 1) {
            let (ith_bit_condition, prefix) = try_join(
                check_each_bit_context.narrow(&BitOpStep::from(i)).multiply(
                    record_id,
                    &less_thaned_bits[i],
                    &all_preceeding_bits_the_same,
                ),
                prefix_equal_context.narrow(&BitOpStep::from(i)).multiply(
                    record_id,
                    &(one.clone() - &xored_bits[i]),
                    &all_preceeding_bits_the_same,
                ),
            )
            .await?;
            all_preceeding_bits_the_same = prefix;
            any_condition_met += &ith_bit_condition;
        }
        let final_index = a.len() - 1;
        let final_bit_condition = check_each_bit_context
            .narrow(&BitOpStep::from(final_index))
            .multiply(
                record_id,
                &less_thaned_bits[final_index],
                &all_preceeding_bits_the_same,
            )
            .await?;
        any_condition_met += &final_bit_condition;
        Ok(any_condition_met)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BitwiseAXorB,
    BitwiseALessThanB,
    CheckEachBit,
    PrefixEqual,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BitwiseAXorB => "bitwise_a_xor_b",
            Self::BitwiseALessThanB => "bitwise_a_lt_b",
            Self::CheckEachBit => "check_each_bit",
            Self::PrefixEqual => "prefix_equal",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::BitwiseLessThan;
    use crate::protocol::context::Context;
    use crate::rand::thread_rng;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::Runner;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::RecordId,
        test_fixture::{into_bits, Reconstruct, TestWorld},
    };
    use proptest::prelude::Rng;
    use rand::{distributions::Standard, prelude::Distribution};

    async fn bitwise_lt<F: Field>(world: &TestWorld, a: F, b: F) -> F
    where
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let input = (into_bits(a), into_bits(b));
        let result = world
            .semi_honest(input.clone(), |ctx, (a_share, b_share)| async move {
                BitwiseLessThan::execute(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    &b_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious(input, |ctx, (a_share, b_share)| async move {
                BitwiseLessThan::execute(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    &b_share,
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

        assert_eq!(one, bitwise_lt(&world, zero, one).await);
        assert_eq!(zero, bitwise_lt(&world, one, zero).await);
        assert_eq!(zero, bitwise_lt(&world, zero, zero).await);
        assert_eq!(zero, bitwise_lt(&world, one, one).await);

        assert_eq!(one, bitwise_lt(&world, c(3_u8), c(7)).await);
        assert_eq!(zero, bitwise_lt(&world, c(21), c(20)).await);
        assert_eq!(zero, bitwise_lt(&world, c(9), c(9)).await);

        assert_eq!(zero, bitwise_lt(&world, zero, c(Fp31::PRIME)).await);
    }

    #[tokio::test]
    pub async fn fp_32bit_prime() {
        let c = Fp32BitPrime::from;
        let zero = Fp32BitPrime::ZERO;
        let one = Fp32BitPrime::ONE;
        let u16_max: u32 = u16::MAX.into();
        let world = TestWorld::new().await;

        assert_eq!(one, bitwise_lt(&world, zero, one).await);
        assert_eq!(zero, bitwise_lt(&world, one, zero).await);
        assert_eq!(zero, bitwise_lt(&world, zero, zero).await);
        assert_eq!(zero, bitwise_lt(&world, one, one).await);

        assert_eq!(one, bitwise_lt(&world, c(3_u32), c(7)).await);
        assert_eq!(zero, bitwise_lt(&world, c(21), c(20)).await);
        assert_eq!(zero, bitwise_lt(&world, c(9), c(9)).await);

        assert_eq!(one, bitwise_lt(&world, c(u16_max), c(u16_max + 1)).await);
        assert_eq!(zero, bitwise_lt(&world, c(u16_max + 1), c(u16_max)).await);
        assert_eq!(
            one,
            bitwise_lt(&world, c(u16_max), c(Fp32BitPrime::PRIME - 1)).await
        );

        assert_eq!(zero, bitwise_lt(&world, zero, c(Fp32BitPrime::PRIME)).await);
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
                Fp32BitPrime::from(a.as_u128() < b.as_u128()),
                bitwise_lt(&world, a, b).await
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
                    Fp31::from(a < b),
                    bitwise_lt(&world, Fp31::from(a), Fp31::from(b)).await
                );
            }
        }
    }
}
