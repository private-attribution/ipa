use super::xor::xor;
use super::{align_bit_lengths, BitOpStep};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{context::Context, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;
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
    async fn xor_all_but_lsb<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let xor = zip(a, b)
            .enumerate()
            .skip(1)
            .rev()
            .map(|(i, (a_bit, b_bit))| {
                let c = ctx.narrow(&BitOpStep::Step(i));
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
    async fn less_than_all_bits<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let less_than = zip(a, b).enumerate().rev().map(|(i, (a_bit, b_bit))| {
            let c = ctx.narrow(&BitOpStep::Step(i));
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
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Replicated<F>, Error> {
        let (a, b) = align_bit_lengths(a, b);

        let (xored_bits, less_thaned_bits) = try_join(
            Self::xor_all_but_lsb(&a, &b, ctx.narrow(&Step::BitwiseAXorB), record_id),
            Self::less_than_all_bits(&a, &b, ctx.narrow(&Step::BitwiseALessThanB), record_id),
        )
        .await?;

        let one = ctx.share_of_one();
        let mut any_condition_met = less_thaned_bits[0].clone();
        let mut all_preceeding_bits_the_same = one.clone() - &(xored_bits[0]);
        let check_each_bit_context = ctx.narrow(&Step::CheckEachBit);
        let prefix_equal_context = ctx.narrow(&Step::PrefixEqual);
        for i in 1..(less_thaned_bits.len() - 1) {
            let (ith_bit_condition, prefix) = try_join(
                check_each_bit_context.narrow(&BitOpStep::Step(i)).multiply(
                    record_id,
                    &less_thaned_bits[i],
                    &all_preceeding_bits_the_same,
                ),
                prefix_equal_context.narrow(&BitOpStep::Step(i)).multiply(
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
            .narrow(&BitOpStep::Step(final_index))
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
