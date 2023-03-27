pub mod accumulate_credit;
pub mod aggregate_credit;
pub mod apply_attribution_window;
pub mod credit_capping;
pub mod input;
pub mod malicious;
pub mod semi_honest;

use crate::{
    error::Error,
    ff::{Field, Gf2},
    protocol::{
        basics::SecureMul, boolean::or::or, context::Context, BasicProtocols, RecordId, Substep,
    },
    repeat64str,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, Linear as LinearSecretSharing,
    },
};
use futures::future::{try_join, try_join_all};

use super::{
    boolean::bitwise_equal::bitwise_equal_gf2,
    context::SemiHonestContext,
    modulus_conversion::{convert_bit, convert_bit_local, BitConversionTriple},
    BitOpStep,
};

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
    S: LinearSecretSharing<F> + SecureMul<C>,
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
        + &condition
            .multiply(&(true_value.clone() - false_value), ctx, record_id)
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
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
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
        let end = num_rows - step_size;
        let next_end = usize::saturating_sub(num_rows, 2 * step_size);
        let depth_i_ctx = ctx.narrow(&InteractionPatternStep::from(depth));
        let new_credit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorCredit)
            .set_total_records(end);
        let credit_or_ctx = depth_i_ctx
            .narrow(&Step::CurrentCreditOrCreditUpdate)
            .set_total_records(end);
        let new_stop_bit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorStopBit)
            .set_total_records(next_end);
        let mut credit_update_futures = Vec::with_capacity(end);
        let mut stop_bit_futures = Vec::with_capacity(end);

        for i in 0..end {
            let c1 = new_credit_ctx.clone();
            let c2 = new_stop_bit_ctx.clone();
            let c3 = credit_or_ctx.clone();
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_credit = &uncapped_credits[i + step_size];
            let current_credit = &uncapped_credits[i];

            credit_update_futures.push(async move {
                let credit_update = current_stop_bit
                    .multiply(sibling_credit, c1, record_id)
                    .await?;
                if first_iteration {
                    Ok(credit_update + current_credit)
                } else {
                    or(c3, record_id, current_credit, &credit_update).await
                }
            });
            if i < next_end {
                let sibling_stop_bit = &stop_bits[i + step_size];
                stop_bit_futures.push(async move {
                    current_stop_bit
                        .multiply(sibling_stop_bit, c2, record_id)
                        .await
                });
            }
        }

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
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    let num_rows = values.len();

    // Each loop the "step size" is doubled. This produces a "binary tree" like behavior
    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let next_end = usize::saturating_sub(num_rows, 2 * step_size);
        let depth_i_ctx = ctx.narrow(&InteractionPatternStep::from(depth));
        let new_value_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorCredit)
            .set_total_records(end);
        let new_stop_bit_ctx = depth_i_ctx
            .narrow(&Step::CurrentStopBitTimesSuccessorStopBit)
            .set_total_records(next_end);
        let mut value_update_futures = Vec::with_capacity(end);
        let mut stop_bit_futures = Vec::with_capacity(end);

        for i in 0..end {
            let c1 = new_value_ctx.clone();
            let c2 = new_stop_bit_ctx.clone();
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_value = &values[i + step_size];
            value_update_futures.push(async move {
                current_stop_bit
                    .multiply(sibling_value, c1, record_id)
                    .await
            });
            if i < next_end {
                let sibling_stop_bit = &stop_bits[i + step_size];
                stop_bit_futures.push(async move {
                    current_stop_bit
                        .multiply(sibling_stop_bit, c2, record_id)
                        .await
                });
            }
        }

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
            .into_iter()
            .enumerate()
            .for_each(|(i, value_update)| {
                values[i] += &value_update;
            });
    }
    Ok(())
}

async fn compute_helper_bits_gf2<C, S>(
    ctx: C,
    sorted_match_keys: &[Vec<S>],
) -> Result<Vec<S>, Error>
where
    C: Context,
    S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    let narrowed_ctx = ctx
        .narrow(&Step::ComputeHelperBits)
        .set_total_records(sorted_match_keys.len() - 1);

    try_join_all(sorted_match_keys.windows(2).enumerate().map(|(i, rows)| {
        let c = narrowed_ctx.clone();
        let record_id = RecordId::from(i);
        async move { bitwise_equal_gf2(c, record_id, &rows[0], &rows[1]).await }
    }))
    .await
}

async fn mod_conv_helper_bits<F>(
    sh_ctx: SemiHonestContext<'_>,
    semi_honest_helper_bits_gf2: &[Replicated<Gf2>],
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    let hb_mod_conv_ctx = sh_ctx
        .narrow(&Step::ModConvHelperBits)
        .set_total_records(semi_honest_helper_bits_gf2.len());

    try_join_all(
        semi_honest_helper_bits_gf2
            .iter()
            .enumerate()
            .map(|(i, gf2_bit)| {
                let bit_triple: BitConversionTriple<Replicated<F>> =
                    convert_bit_local::<F, Gf2>(sh_ctx.role(), 0, gf2_bit);
                let record_id = RecordId::from(i);
                let c = hb_mod_conv_ctx.clone();
                // TODO: I think this is a mistake.
                // In the malicious case, I think this should be upgraded *first*
                // before calling `convert_bit`
                async move { convert_bit(c, record_id, &bit_triple).await }
            }),
    )
    .await
}

async fn mod_conv_gf2_vec<F>(
    sh_ctx: SemiHonestContext<'_>,
    record_id: RecordId,
    semi_honest_gf2_bits: &[Replicated<Gf2>],
) -> Result<Vec<Replicated<F>>, Error>
where
    F: Field,
{
    try_join_all(semi_honest_gf2_bits.iter().enumerate().map(|(i, gf2_bit)| {
        let bit_triple: BitConversionTriple<Replicated<F>> =
            convert_bit_local::<F, Gf2>(sh_ctx.role(), 0, gf2_bit);
        let c = sh_ctx.narrow(&BitOpStep::from(i));
        // TODO: I think this is a mistake.
        // In the malicious case, I think this should be upgraded *first*
        // before calling `convert_bit`
        async move { convert_bit(c, record_id, &bit_triple).await }
    }))
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(clippy::enum_variant_names)]
enum Step {
    CurrentStopBitTimesSuccessorCredit,
    CurrentStopBitTimesSuccessorStopBit,
    CurrentCreditOrCreditUpdate,
    ComputeHelperBits,
    ModConvHelperBits,
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
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::ModConvHelperBits => "mod_conv_helper_bits",
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
