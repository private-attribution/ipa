use super::BitOpStep;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::boolean::or::or;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::mul::SecureMul;
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::Replicated;
use futures::future::try_join_all;
use std::iter::zip;

/// This is an implementation of Bitwise Sum on bitwise-shared numbers.
///
/// `BitwiseSum` takes inputs `[a]_B = ([a_0]_p,...,[a_(l-1)]_p)` where
/// `a_0,...,a_(l-1) ∈ {0,1} ⊆ F_p` and `[b]_B = ([b_0]_p,...,[b_(l-1)]_p)` where
/// `b_0,...,b_(l-1) ∈ {0,1} ⊆ F_p`, then computes `[d]_B = ([d_0]_p,...,[d_l]_p)`
/// of `a + b`.
///
/// Note that the index notation of the inputs is `0..l-1`, whereas the output
/// index notation is `0..l`. This means that the output of this protocol will be
/// "`l+1`"-bit long bitwise secret shares, where `l = |[a]_B|`.
pub struct BitwiseSum {}

impl BitwiseSum {
    async fn multiply_all_the_bits<F: Field>(
        a: &[Replicated<F>],
        b: &[Replicated<F>],
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let both_one = zip(a, b).enumerate().map(|(i, (a_bit, b_bit))| {
            let c = ctx.narrow(&BitOpStep::Step(i));
            async move { c.multiply(record_id, a_bit, b_bit).await }
        });
        try_join_all(both_one).await
    }

    #[allow(dead_code)]
    #[allow(clippy::many_single_char_names)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        a: &[Replicated<F>],
        b: &[Replicated<F>],
    ) -> Result<Vec<Replicated<F>>, Error> {
        debug_assert_eq!(a.len(), b.len(), "Length of the input bits must be equal");

        let both_bits_one =
            Self::multiply_all_the_bits(a, b, ctx.narrow(&Step::MultiplyAllTheBits), record_id)
                .await?;
        let mut xored_bits = Vec::with_capacity(a.len());
        for i in 0..a.len() {
            xored_bits.push(&a[i] + &b[i] - &(both_bits_one[i].clone() * F::from(2)));
        }
        let mut output = Vec::with_capacity(a.len() + 1);
        output.push(xored_bits[0].clone());

        let carry_and_xored_bit_ctx = ctx.narrow(&Step::CarryAndXORedBit);
        let either_carry_condition_ctx = ctx.narrow(&Step::EitherCarryCondition);

        let mut carry = both_bits_one[0].clone();
        for i in 1..a.len() {
            let carry_and_xored_bit = carry_and_xored_bit_ctx
                .narrow(&BitOpStep::Step(i))
                .multiply(record_id, &carry, &xored_bits[i])
                .await?;
            let next_carry = or(
                either_carry_condition_ctx.narrow(&BitOpStep::Step(i)),
                record_id,
                &carry_and_xored_bit,
                &both_bits_one[i],
            )
            .await?;
            output.push(&a[i] + &b[i] + &carry - &(next_carry.clone() * F::from(2)));
            carry = next_carry;
        }
        output.push(carry);
        Ok(output)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    MultiplyAllTheBits,
    CarryAndXORedBit,
    EitherCarryCondition,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MultiplyAllTheBits => "multiply_all_the_bits",
            Self::CarryAndXORedBit => "carry_and_xored_bit",
            Self::EitherCarryCondition => "either_carry_condition",
        }
    }
}
