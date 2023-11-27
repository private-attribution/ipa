pub mod accumulate_credit;
pub mod aggregate_credit;
pub mod apply_attribution_window;
pub mod credit_capping;
pub mod input;

use std::iter::{once as iter_once, zip};

use futures::{
    future::try_join,
    stream::{iter as stream_iter, TryStreamExt},
};
use ipa_macros::Step;

use self::{
    accumulate_credit::accumulate_credit, aggregate_credit::aggregate_credit,
    apply_attribution_window::apply_attribution_window, credit_capping::credit_capping,
    input::ApplyAttributionWindowInputRow,
};
use crate::{
    error::Error,
    ff::{Field, Gf2, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    protocol::{
        basics::SecureMul,
        boolean::{bitwise_equal::bitwise_equal_gf2, or::or},
        context::{Context, UpgradableContext, UpgradedContext, Validator},
        ipa::{ArithmeticallySharedIPAInputs, BinarySharedIPAInputs},
        modulus_conversion::convert_bits,
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        Linear as LinearSecretSharing, LinearRefOps,
    },
    seq_join::assert_send,
};

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "attribute", skip_all)]
pub async fn secure_attribution<V, VB, C, S, SB, F>(
    validator: V,
    binary_validator: VB,
    arithmetically_shared_values: Vec<ArithmeticallySharedIPAInputs<F, S>>,
    binary_shared_values: Vec<BinarySharedIPAInputs<SB>>,
    config: IpaQueryConfig,
) -> Result<Vec<Replicated<F>>, Error>
where
    V: Validator<C, F>,
    VB: Validator<C, Gf2>,
    C: UpgradableContext<Validator<F> = V>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    for<'a> &'a S: LinearRefOps<'a, S, F>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB> + Context,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    for<'a> &'a SB: LinearRefOps<'a, SB, Gf2>,
    F: PrimeField + ExtendableField,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
{
    let row_count = arithmetically_shared_values.len();
    assert_eq!(row_count, binary_shared_values.len());
    let m_ctx = validator.context();
    let m_binary_ctx = binary_validator.context();

    // There are one fewer helper bits than there are input rows.  Same for stop bits.
    // This propagates throughout aggregation (all the code understands this).
    // And a breakdown for the last row isn't necessary because an impression on that row can't convert.
    // So we drop the last breakdown key right away.
    let helper_bits_gf2 = compute_helper_bits_gf2(m_binary_ctx, &binary_shared_values).await?;
    let breakdown_key_bits_gf2: Vec<_> = binary_shared_values
        .iter()
        .map(|x| x.breakdown_key.clone())
        .take(row_count - 1)
        .collect();

    let (validated_helper_bits_gf2, validated_breakdown_key_bits_gf2) = binary_validator
        .validate((helper_bits_gf2, breakdown_key_bits_gf2))
        .await?;

    let convert_ctx = m_ctx
        .narrow(&AttributionStep::ConvertHelperBits)
        .set_total_records(validated_helper_bits_gf2.len());
    let helper_bits = convert_bits(convert_ctx, stream_iter(validated_helper_bits_gf2), 0..1)
        .map_ok(|b| b.into_iter().next().unwrap()) // TODO: simplify single-bit conversion
        .try_collect::<Vec<_>>()
        .await?;

    let is_trigger_bits = arithmetically_shared_values
        .iter()
        .map(|x| x.is_trigger_bit.clone())
        .collect::<Vec<_>>();
    let stop_bits = compute_stop_bits(m_ctx.clone(), &is_trigger_bits, &helper_bits)
        .await?
        .collect::<Vec<_>>();

    // Semantically, `helper_bit` indicates if the preceding row has the same value of `match_key`.
    // For the first row, this cannot be the case as there is no preceding row, so we just provide a zero.
    debug_assert_eq!(arithmetically_shared_values.len(), helper_bits.len() + 1);
    let attribution_input_rows = zip(
        arithmetically_shared_values,
        iter_once(S::ZERO).chain(helper_bits),
    )
    .map(|(arithmetic, hb)| {
        ApplyAttributionWindowInputRow::new(
            arithmetic.timestamp,
            arithmetic.is_trigger_bit,
            hb,
            arithmetic.trigger_value,
        )
    })
    .collect::<Vec<_>>();

    let windowed_reports = apply_attribution_window(
        m_ctx.narrow(&AttributionStep::ApplyAttributionWindow),
        &attribution_input_rows,
        &stop_bits,
        config.attribution_window_seconds,
    )
    .await?;

    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&AttributionStep::AccumulateCredit),
        &windowed_reports,
        &stop_bits,
        config.per_user_credit_cap,
        config.attribution_window_seconds,
    )
    .await?;

    let user_capped_credits = credit_capping(
        m_ctx.narrow(&AttributionStep::PerformUserCapping),
        &accumulated_credits,
        config.per_user_credit_cap,
    )
    .await?;

    let (validator, output) = aggregate_credit(
        validator,
        validated_breakdown_key_bits_gf2.into_iter(),
        user_capped_credits.into_iter(),
        config.max_breakdown_key,
    )
    .await?;

    //Validate before returning the result to the report collector
    validator.validate(output).await
}

#[derive(Step)]
pub(crate) enum AttributionStep {
    ConvertHelperBits,
    ApplyAttributionWindow,
    AccumulateCredit,
    PerformUserCapping,
}

///
/// Computes a "prefix-OR" operation starting on each element in the list.
/// Stops as soon as `helper_bits` indicates the following rows are not from
/// the same `match key`.
///
/// `should_add_on_first_iteration` is a performance optimization.
/// If the caller has foreknowledge that there will never be any two adjacent
/// rows, *both* containing a 1, then it is safe to pass `true`, which will
/// simply add values on the first iteration (thereby saving one multiplication
/// per row). If the caller does not know of any such guarantee, `false` should
/// be passed.
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
    should_add_on_first_iteration: bool,
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
                if first_iteration && should_add_on_first_iteration {
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
            assert_send(ctx.try_join(stop_bit_futures)),
            assert_send(ctx.try_join(credit_update_futures)),
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
            assert_send(ctx.try_join(stop_bit_futures)),
            assert_send(ctx.try_join(value_update_futures)),
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

/// Stop Bits are boolean values (1 or 0) and indicate if values should continue to accumulate, or not.
/// In the case of attribution, multiple trigger reports might all be attributed to a single source
/// report in the case that there is a source report followed by multiple trigger reports, all having
/// the same value of match key.
///
/// Stop bits are the AND (i.e., multiply) of "is trigger bit" and "helper bit" from the same row.
/// Note, the `helper_bits` provided here skip the first row as that value is known already.
/// The output of the function also skips this first row.
async fn compute_stop_bits<F, S, C>(
    ctx: C,
    is_trigger_bits: &[S],
    helper_bits: &[S],
) -> Result<impl Iterator<Item = S>, Error>
where
    F: Field,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
    C: Context,
{
    let stop_bits_ctx = ctx
        .narrow(&Step::ComputeStopBits)
        .set_total_records(is_trigger_bits.len() - 1);

    // Note that the helper bits provided to this function skip the first row,
    // so this functions starts from the second row of trigger bits.
    let futures = zip(&is_trigger_bits[1..], helper_bits).enumerate().map(
        |(i, (is_trigger_bit, helper_bit))| {
            let c = stop_bits_ctx.clone();
            let record_id = RecordId::from(i);
            async move { is_trigger_bit.multiply(helper_bit, c, record_id).await }
        },
    );
    Ok(ctx.try_join(futures).await?.into_iter())
}

async fn compute_helper_bits_gf2<C, S>(
    ctx: C,
    binary_shared_values: &[BinarySharedIPAInputs<S>],
) -> Result<Vec<S>, Error>
where
    C: Context,
    S: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
    for<'a> &'a S: LinearRefOps<'a, S, Gf2>,
{
    let narrowed_ctx = ctx
        .narrow(&Step::ComputeHelperBits)
        .set_total_records(binary_shared_values.len() - 1);

    ctx.try_join(
        binary_shared_values
            .windows(2)
            .enumerate()
            .map(|(i, rows)| {
                let c = narrowed_ctx.clone();
                let record_id = RecordId::from(i);
                async move {
                    bitwise_equal_gf2(c, record_id, &rows[0].match_key, &rows[1].match_key).await
                }
            }),
    )
    .await
}

#[derive(Step)]
#[allow(clippy::enum_variant_names)]
pub(in crate::protocol) enum Step {
    CurrentStopBitTimesSuccessorCredit,
    CurrentStopBitTimesSuccessorStopBit,
    CurrentCreditOrCreditUpdate,
    ComputeHelperBits,
    ComputeStopBits,
}

#[derive(Step)]
pub(crate) enum InteractionPatternStep {
    #[dynamic(64)]
    Depth(usize),
}

impl From<usize> for InteractionPatternStep {
    fn from(v: usize) -> Self {
        Self::Depth(v)
    }
}
