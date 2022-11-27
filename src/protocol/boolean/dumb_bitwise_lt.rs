use super::xor::xor;
use super::BitOpStep;
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
    /// Step 1. `for i=0..l-1, [e_i] = XOR([a_i], [b_i])`
    ///
    /// # Example
    /// ```ignore
    ///   //  bit-0         bit-7
    ///   //    v             v
    ///   [a] = 1 0 1 0 1 0 0 0   // 21 in little-endian
    ///   [b] = 0 1 1 1 1 0 0 0   // 30 in little-endian
    ///   [e] = 1 1 0 1 0 0 0 0
    /// ```
    async fn xor_all_but_the_last_bit<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let xor = zip(a, b)
            .enumerate()
            .rev()
            .take(a.len() - 1)
            .map(|(i, (a_bit, b_bit))| {
                let c = ctx.narrow(&BitOpStep::Step(i));
                async move { xor(c, record_id, a_bit, b_bit).await }
            });
        try_join_all(xor).await
    }

    /// Step 2. `([f_(l-1)]..[f_0]) = PrefixOr([e_(l-1)]..[e_0])`
    ///
    /// We compute `PrefixOr` of [e] in the reverse order. Remember that the
    /// inputs are in little-endian format. In this step, we try to find the
    /// smallest `i` (or MSB since `e` is reversed) where `a_i != b_i`. The
    /// output is in big-endian, note that the ordering of `[f]` in the notation
    /// above is also reversed as in `([f_(l-1)]..[f_0])`, hence we reverse the
    /// vector once again before returning.
    ///
    /// # Example
    /// ```ignore
    ///   //  bit-0         bit-7
    ///   //    v             v
    ///   [e] = 1 1 0 1 0 0 0 0
    ///   [f] = 0 0 0 0 1 1 1 1
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

    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Replicated<F>, Error> {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");
        let (xored_bits, less_thaned_bits) = try_join(
            Self::xor_all_but_the_last_bit(a, b, ctx.narrow(&Step::BitwiseAXorB), record_id),
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
