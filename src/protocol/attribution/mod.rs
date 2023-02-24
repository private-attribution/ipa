pub mod aggregate_credit;
pub mod credit_capping;
pub mod input;

pub(crate) mod accumulate_credit;
use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::SecureMul, boolean::or::or, context::Context, BasicProtocols, RecordId, Substep,
    },
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
    C: Context,
    S: ArithmeticSecretSharing<F> + SecureMul<C>,
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
        + &S::multiply(
            ctx,
            record_id,
            condition,
            &(true_value.clone() - false_value),
        )
        .await?)
}

///
/// Computes a "prefix-OR" operation starting on each element in the list.
/// Stops as soon as `helper_bits` indicates the following rows are not from
/// the same `match key`.
///
/// ## Errors
/// Fails if the multiplication protocol fails.
///
/// ## Panics
/// Nah, it doesn't.
///
pub async fn prefix_or_binary_tree_style<F, C, S>(
    ctx: C,
    stop_bits: &[S],
    uncapped_credits: &[S],
) -> Result<Vec<S>, Error>
where
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + BasicProtocols<C, F>,
{
    assert_eq!(stop_bits.len() + 1, uncapped_credits.len());

    let num_rows = uncapped_credits.len();

    let mut uncapped_credits = uncapped_credits.to_owned();

    // This vector is updated in each iteration to help accumulate credits
    // and determine when to stop accumulating.
    let mut stop_bits = stop_bits.to_owned();

    // Each loop the "step size" is doubled. This produces a "binary tree" like behavior
    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let first_iteration = step_size == 1;
        let last_iteration = step_size * 2 >= num_rows;
        let end = num_rows - step_size;
        let depth_i_ctx = ctx.narrow(&InteractionPatternStep::from(depth));
        let new_credit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorCredit)
            .set_total_records(end);
        let credit_or_ctx = depth_i_ctx
            .narrow(&Step::CurrentCreditOrCreditUpdate)
            .set_total_records(end);
        let new_stop_bit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorStopBit)
            .set_total_records(end - 1);
        let mut credit_update_futures = Vec::with_capacity(end);
        let mut stop_bit_futures = Vec::with_capacity(end);

        for i in 0..end {
            let last_row = i == end - 1;
            let c1 = new_credit_ctx.clone();
            let c2 = new_stop_bit_ctx.clone();
            let c3 = credit_or_ctx.clone();
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_credit = &uncapped_credits[i + step_size];
            let current_credit = &uncapped_credits[i];

            credit_update_futures.push(async move {
                let credit_update =
                    S::multiply(c1, record_id, current_stop_bit, sibling_credit).await?;
                if first_iteration {
                    Ok(credit_update + current_credit)
                } else {
                    or(c3, record_id, current_credit, &credit_update).await
                }
            });
            if !last_iteration && !last_row {
                let sibling_stop_bit = &stop_bits[i + step_size];
                stop_bit_futures.push(async move {
                    S::multiply(c2, record_id, current_stop_bit, sibling_stop_bit).await
                });
            }
        }

        let credit_updates = if last_iteration {
            try_join_all(credit_update_futures).await?
        } else {
            let (stop_bit_updates, credit_updates) = try_join(
                try_join_all(stop_bit_futures),
                try_join_all(credit_update_futures),
            )
            .await?;

            stop_bit_updates
                .into_iter()
                .enumerate()
                .for_each(|(i, stop_bit_update)| {
                    stop_bits[i] = stop_bit_update;
                });
            credit_updates
        };
        credit_updates
            .into_iter()
            .enumerate()
            .for_each(|(i, credit_update)| {
                uncapped_credits[i] = credit_update;
            });
    }
    Ok(uncapped_credits)
}

///
/// Computes `SUM(credits[i] through credits[i + n])` where `n` is the number of "matching rows", as indicated by the `helper_bits`
/// This result is saved as `credits\[i\]`.
///
/// Helper bits should be a sharing of either `1` or `0` for each row, indicating if that row "matches" the row preceding it.
///
/// ## Errors
/// Fails if the multiplication protocol fails.
///
/// ## Panics
/// Nah, it doesn't.
///
pub async fn do_the_binary_tree_thing<F, C, S>(
    ctx: C,
    mut stop_bits: Vec<S>,
    values: &mut [S],
) -> Result<(), Error>
where
    F: Field,
    C: Context,
    S: ArithmeticSecretSharing<F> + SecureMul<C>,
{
    let num_rows = values.len();

    // Each loop the "step size" is doubled. This produces a "binary tree" like behavior
    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let last_iteration = step_size * 2 >= num_rows;
        let end = num_rows - step_size;
        let depth_i_ctx = ctx.narrow(&InteractionPatternStep::from(depth));
        let new_value_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorCredit)
            .set_total_records(end);
        let new_stop_bit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorStopBit)
            .set_total_records(end - 1);
        let mut value_update_futures = Vec::with_capacity(end);
        let mut stop_bit_futures = Vec::with_capacity(end);

        for i in 0..end {
            let last_row = i == end - 1;
            let c1 = new_value_ctx.clone();
            let c2 = new_stop_bit_ctx.clone();
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_value = &values[i + step_size];
            value_update_futures.push(async move {
                S::multiply(c1, record_id, current_stop_bit, sibling_value).await
            });
            if !last_iteration && !last_row {
                let sibling_stop_bit = &stop_bits[i + step_size];
                stop_bit_futures.push(async move {
                    S::multiply(c2, record_id, current_stop_bit, sibling_stop_bit).await
                });
            }
        }

        let value_updates = if last_iteration {
            try_join_all(value_update_futures).await?
        } else {
            let (stop_bit_updates, value_updates) = try_join(
                try_join_all(stop_bit_futures),
                try_join_all(value_update_futures),
            )
            .await?;

            stop_bit_updates
                .into_iter()
                .enumerate()
                .for_each(|(i, stop_bit_update)| {
                    stop_bits[i] = stop_bit_update;
                });
            value_updates
        };
        value_updates
            .into_iter()
            .enumerate()
            .for_each(|(i, value_update)| {
                values[i] += &value_update;
            });
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
enum Step {
    CurrentStopBitTimesSuccessorCredit,
    CurrentStopBitTimesSuccessorStopBit,
    CurrentCreditOrCreditUpdate,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::CurrentStopBitTimesSuccessorCredit => "current_stop_bit_times_successor_credit",
            Self::CurrentStopBitTimesSuccessorStopBit => {
                "current_stop_bit_times_successor_stop_bit"
            }
            Self::CurrentCreditOrCreditUpdate => "current_credit_or_credit_update",
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
