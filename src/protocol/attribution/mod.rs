pub mod aggregate_credit;
pub mod credit_capping;
pub mod input;

pub(crate) mod accumulate_credit;

use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, RecordId, Substep},
    repeat64str,
    secret_sharing::Arithmetic as ArithmeticSecretSharing,
};
use futures::future::{try_join, try_join_all};

/// Returns `true_value` if `condition` is a share of 1, else `false_value`.
async fn if_else<F, C, S>(
    ctx: C,
    record_id: RecordId,
    condition: &S,
    true_value: &S,
    false_value: &S,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F>,
{
    // If `condition` is a share of 1 (true), then
    //   = false_value + 1 * (true_value - false_value)
    //   = false_value + true_value - false_value
    //   = true_value
    //
    // If `condition` is a share of 0 (false), then
    //   = false_value + 0 * (true_value - false_value)
    //   = false_value
    Ok(false_value.clone()
        + &ctx
            .multiply(record_id, condition, &(true_value.clone() - false_value))
            .await?)
}

///
/// Computes `SUM(credits[i] through credits[i + n])` where `n` is the number of "matching rows", as indicated by the `helper_bits`
/// This result is saved as credits[i].
///
/// Helper bits should be a sharing of either `1` or `0` for each row, indicating if that row "matches" the row preceding it.
///
/// ## Errors
/// Fails if the multiplication protocol fails.
///
/// ## Panics
/// Nah, it doesn't.
///
pub async fn do_the_binary_tree_thing<'a, F, C, S, I>(
    ctx: C,
    helper_bits: &[S],
    credits: I,
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: ArithmeticSecretSharing<F> + 'a,
    I: Iterator<Item = &'a S>,
{
    let num_rows = helper_bits.len() + 1;
    let depth_0_ctx = ctx
        .narrow(&InteractionPatternStep::from(0))
        .set_total_records(num_rows - 1);

    let mut last = None;
    let credit_and_next_credit = credits.map(|x| (last.replace(x.clone()), x)).skip(1);

    let mut credits = try_join_all(credit_and_next_credit.zip(helper_bits).enumerate().map(
        |(i, ((current_credit, next_credit), helper_bit))| {
            let c = depth_0_ctx.clone();
            let record_id = RecordId::from(i);
            async move {
                Ok::<_, Error>(
                    current_credit.unwrap()
                        + &c.multiply(record_id, helper_bit, next_credit).await?,
                )
            }
        },
    ))
    .await?;
    // This is crap and will resize the vector... it was too hard to fix...
    credits.push(last.unwrap());

    // Create stop_bit vector.
    // This vector is updated in each iteration to help accumulate values
    // and determine when to stop accumulating.
    let mut stop_bits = helper_bits.to_owned();
    stop_bits.push(ctx.share_known_value(F::ONE));

    // Each loop the "step size" is doubled. This produces a "binary tree" like behavior
    for (depth, step_size) in std::iter::successors(Some(2_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let depth_i_ctx = ctx
            .narrow(&InteractionPatternStep::from(depth + 1))
            .set_total_records(end);
        let b_times_sibling_credit_ctx = depth_i_ctx.narrow(&Step::BTimesSuccessorCredit);
        let b_times_sibling_stop_bit_ctx = depth_i_ctx.narrow(&Step::BTimesSuccessorStopBit);
        let mut futures = Vec::with_capacity(end);

        for i in 0..end {
            let c1 = depth_i_ctx.clone();
            let c2 = b_times_sibling_credit_ctx.clone();
            let c3 = b_times_sibling_stop_bit_ctx.clone();
            let record_id = RecordId::from(i);
            let sibling_helper_bit = &helper_bits[i + step_size - 1];
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_credit = &credits[i + step_size];
            futures.push(async move {
                let b = c1
                    .multiply(record_id, current_stop_bit, sibling_helper_bit)
                    .await?;

                try_join(
                    c2.multiply(record_id, &b, sibling_credit),
                    c3.multiply(record_id, &b, sibling_stop_bit),
                )
                .await
            });
        }

        let results = try_join_all(futures).await?;

        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                credits[i] += &credit;
                stop_bits[i] = stop_bit;
            });
    }
    Ok(credits)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BTimesSuccessorCredit,
    BTimesSuccessorStopBit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BTimesSuccessorCredit => "b_times_successor_credit",
            Self::BTimesSuccessorStopBit => "b_times_successor_stop_bit",
        }
    }
}

struct InteractionPatternStep(usize);

impl Substep for InteractionPatternStep {}

impl AsRef<str> for InteractionPatternStep {
    fn as_ref(&self) -> &str {
        const DEPTH: [&str; 64] = repeat64str!["depth"];
        DEPTH[self.0]
    }
}

impl From<usize> for InteractionPatternStep {
    fn from(v: usize) -> Self {
        Self(v)
    }
}
