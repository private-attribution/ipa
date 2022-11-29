use super::{align_bit_lengths, BitOpStep};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::boolean::or::or;
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::SecretSharing;
use futures::future::try_join_all;
use std::iter::zip;

async fn multiply_all_the_bits<F, C, S>(
    a: &[S],
    b: &[S],
    ctx: C,
    record_id: RecordId,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let both_one = zip(a, b).enumerate().map(|(i, (a_bit, b_bit))| {
        let c = ctx.narrow(&BitOpStep::Step(i));
        async move { c.multiply(record_id, a_bit, b_bit).await }
    });
    try_join_all(both_one).await
}

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
///
/// Really simple logic. Just follows the way you do addition in grade school
/// Starting from the least significant digit add up the digits, carrying when required.
///
/// For the very first digit, the output is `a_0 XOR b_0` and it carries `a_0 * b_0`
/// For all the following digits, we need to carry if EITHER:
/// `a_i` and `b_i` are both one, OR
/// one of `a_i` and `b_i` are one AND the carry digit is also one
/// we can compute the first condition as `a_i * b_i`
/// the second condition is `XOR(a_i, b_i) * carry_i`
/// Finally, each digit of the output can be found by just summing up `a_i`, `b_i` and `carry_i`,
/// then subtracting 2 if `carry_{i+1} == 1`.
#[allow(dead_code)]
#[allow(clippy::many_single_char_names)]
pub async fn bitwise_sum<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &[S],
    b: &[S],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let (a, b) = align_bit_lengths(a, b); // TODO: remove
    let both_bits_one =
        multiply_all_the_bits(&a, &b, ctx.narrow(&Step::MultiplyAllTheBits), record_id).await?;
    let mut xored_bits = Vec::with_capacity(a.len());
    for i in 0..a.len() {
        xored_bits.push(-(both_bits_one[i].clone() * F::from(2)) + &a[i] + &b[i]);
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
        output.push(-(next_carry.clone() * F::from(2)) + &a[i] + &b[i] + &carry);
        carry = next_carry;
    }
    output.push(carry);
    Ok(output)
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
