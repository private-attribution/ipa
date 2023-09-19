use std::iter::repeat;

use futures_util::future::try_join_all;
use ipa_macros::step;
use strum::AsRefStr;

use super::step::BitOpStep;
use crate::{
    error::Error,
    ff::{Field, Gf2},
    protocol::{
        context::{UpgradableContext, UpgradedContext, Validator},
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing,
    },
};

pub struct PrfShardedIpaInputRow<SB: LinearSecretSharing<Gf2>> {
    prf_of_match_key: u64,
    is_trigger_bit: SB,
    breakdown_key: Vec<SB>,
    trigger_value: Vec<SB>,
}

struct InputsRequiredFromPrevRow<SB: LinearSecretSharing<Gf2>> {
    ever_encountered_a_source_event: SB,
    attributed_breakdown_key_bits: Vec<SB>,
    saturating_sum: Vec<SB>,
    is_saturated: SB,
    difference_to_cap: Vec<SB>,
}

pub struct CappedAttributionOutputs<SB: LinearSecretSharing<Gf2>> {
    did_trigger_get_attributed: SB,
    attributed_breakdown_key_bits: Vec<SB>,
    capped_attributed_trigger_value: Vec<SB>,
}

#[step]
pub(crate) enum Step {
    BinaryValidator,
    EverEncounteredSourceEvent,
    DidTriggerGetAttributed,
    AttributedBreakdownKey,
    AttributedTriggerValue,
    ComputeSaturatingSum,
    IsSaturatedAndPrevRowNotSaturated,
    ComputeDifferenceToCap,
    ComputedCappedAttributedTriggerValueNotSaturatedCase,
    ComputedCappedAttributedTriggerValueJustSaturatedCase,
}

/// Sub-protocol of the PRF-sharded IPA Protocol
///
/// After the computation of the per-user PRF, addition of dummy records and shuffling,
/// the PRF column can be revealed. After that, all of the records corresponding to a single
/// device can be processed together.
///
/// This circuit expects to receive records from multiple users,
/// but with all of the records from a given user adjacent to one another, and in time order.
///
/// This circuit will compute attribution, and per-user capping.
///
/// The output of this circuit is the input to the next stage: Aggregation.
///
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
pub async fn attribution_and_capping_and_aggregation<C, SB, F>(
    sh_ctx: C,
    input_rows: &[PrfShardedIpaInputRow<SB>],
    num_breakdown_key_bits: usize,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<Vec<CappedAttributionOutputs<SB>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
{
    assert!(num_saturating_sum_bits > num_trigger_value_bits);
    assert!(num_trigger_value_bits > 0);
    assert!(num_breakdown_key_bits > 0);

    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();

    let mut output = vec![];

    assert!(input_rows.len() > 0);
    let first_row = &input_rows[0];
    let mut prev_prf = first_row.prf_of_match_key;
    let mut prev_row_inputs = initialize_new_device_attribution_variables(
        SB::share_known_value(&binary_m_ctx, Gf2::ONE),
        first_row,
        num_trigger_value_bits,
        num_saturating_sum_bits,
    );
    let mut i: usize = 1;
    while i < input_rows.len() {
        let cur_row = &input_rows[i];
        if prev_prf != cur_row.prf_of_match_key {
            prev_prf = cur_row.prf_of_match_key;
            prev_row_inputs = initialize_new_device_attribution_variables(
                SB::share_known_value(&binary_m_ctx, Gf2::ONE),
                cur_row,
                num_trigger_value_bits,
                num_saturating_sum_bits,
            );
        } else {
            // Do some actual computation
            let (inputs_required_for_next_row, capped_attribution_outputs) =
                compute_row_with_previous(
                    binary_m_ctx.clone(),
                    cur_row,
                    &prev_row_inputs,
                    num_breakdown_key_bits,
                    num_trigger_value_bits,
                    num_saturating_sum_bits,
                )
                .await?;
            output.push(capped_attribution_outputs);
            prev_row_inputs = inputs_required_for_next_row;
        }
        i += 1;
    }

    Ok(output)
}

fn initialize_new_device_attribution_variables<SB>(
    share_of_one: SB,
    input_row: &PrfShardedIpaInputRow<SB>,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> InputsRequiredFromPrevRow<SB>
where
    SB: LinearSecretSharing<Gf2>,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_source_event: share_of_one - &input_row.is_trigger_bit,
        attributed_breakdown_key_bits: input_row.breakdown_key.clone(),
        saturating_sum: vec![SB::ZERO; num_saturating_sum_bits],
        is_saturated: SB::ZERO,
        difference_to_cap: vec![SB::ZERO; num_trigger_value_bits],
    }
}

///
/// Returns (sum_bit, carry_out)
///
async fn one_bit_adder<C, SB>(
    ctx: C,
    record_id: RecordId,
    x: &SB,
    y: &SB,
    carry_in: &SB,
) -> Result<(SB, SB), Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    // compute sum bit as x XOR y XOR carry_in
    let sum_bit = x.clone() + y + carry_in;

    let x_xor_carry_in = x.clone() + carry_in;
    let y_xor_carry_in = y.clone() + carry_in;
    let carry_out = x_xor_carry_in
        .multiply(&y_xor_carry_in, ctx, record_id)
        .await?
        + carry_in;

    Ok((sum_bit, carry_out))
}

async fn compute_saturating_sum<C, SB>(
    ctx: C,
    record_id: RecordId,
    cur_value: &Vec<SB>,
    prev_sum: &Vec<SB>,
    prev_is_saturated: &SB,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<(Vec<SB>, SB), Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    assert!(cur_value.len() == num_trigger_value_bits);
    assert!(prev_sum.len() == num_saturating_sum_bits);

    let mut carry_in = SB::ZERO;
    let mut output = vec![];
    for i in 0..num_saturating_sum_bits {
        let c = ctx.narrow(&BitOpStep::from(i));
        let (sum_bit, carry_out) = if i < num_trigger_value_bits {
            one_bit_adder(c, record_id, &cur_value[i], &prev_sum[i], &carry_in).await?
        } else {
            one_bit_adder(c, record_id, &SB::ZERO, &prev_sum[i], &carry_in).await?
        };

        output.push(sum_bit);
        carry_in = carry_out;
    }
    let updated_is_saturated = -carry_in
        .clone()
        .multiply(
            prev_is_saturated,
            ctx.narrow(&BitOpStep::from(num_saturating_sum_bits)),
            record_id,
        )
        .await?
        + &carry_in
        + prev_is_saturated;
    Ok((output, updated_is_saturated))
}

///
/// Returns (difference_bit, carry_out)
///
async fn one_bit_subtractor<C, SB>(
    ctx: C,
    record_id: RecordId,
    x: &SB,
    y: &SB,
    carry_in: &SB,
) -> Result<(SB, SB), Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    // compute difference bit as not_y XOR x XOR carry_in
    let difference_bit = SB::share_known_value(&ctx, Gf2::ONE) - y + x + carry_in;

    let x_xor_carry_in = x.clone() + carry_in;
    let y_xor_carry_in = y.clone() + carry_in;
    let not_y_xor_carry_in = SB::share_known_value(&ctx, Gf2::ONE) - &y_xor_carry_in;

    let carry_out = x_xor_carry_in
        .multiply(&not_y_xor_carry_in, ctx, record_id)
        .await?
        + carry_in;

    Ok((difference_bit, carry_out))
}

///
/// TODO: optimize this
/// We can avoid doing this many multiplications given the foreknowledge that we are always subtracting from zero
/// There's also no reason to compute the carry_out for the final bit since it will go unused
///
async fn compute_truncated_difference_to_cap<C, SB>(
    ctx: C,
    record_id: RecordId,
    cur_sum: &Vec<SB>,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<Vec<SB>, Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    assert!(cur_sum.len() == num_saturating_sum_bits);

    let mut carry_in = SB::share_known_value(&ctx, Gf2::ONE);
    let mut output = vec![];
    for i in 0..num_trigger_value_bits {
        let c = ctx.narrow(&BitOpStep::from(i));
        let (difference_bit, carry_out) =
            one_bit_subtractor(c, record_id, &SB::ZERO, &cur_sum[i], &carry_in).await?;

        output.push(difference_bit);
        carry_in = carry_out;
    }
    Ok(output)
}

async fn compute_row_with_previous<C, SB>(
    ctx: C,
    input_row: &PrfShardedIpaInputRow<SB>,
    inputs_required_from_previous_row: &InputsRequiredFromPrevRow<SB>,
    num_breakdown_key_bits: usize,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<(InputsRequiredFromPrevRow<SB>, CappedAttributionOutputs<SB>), Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    assert!(input_row.breakdown_key.len() == num_breakdown_key_bits);
    assert!(
        inputs_required_from_previous_row
            .attributed_breakdown_key_bits
            .len()
            == num_breakdown_key_bits
    );
    assert!(input_row.trigger_value.len() == num_trigger_value_bits);
    assert!(inputs_required_from_previous_row.saturating_sum.len() == num_saturating_sum_bits);

    let record_id = RecordId(0);
    let share_of_one = SB::share_known_value(&ctx, Gf2::ONE);

    // TODO: compute ever_encountered_a_source_event and attributed_breakdown_key_bits in parallel
    let ever_encountered_a_source_event = input_row
        .is_trigger_bit
        .multiply(
            &inputs_required_from_previous_row.ever_encountered_a_source_event,
            ctx.narrow(&Step::EverEncounteredSourceEvent),
            record_id,
        )
        .await?
        + &share_of_one
        - &input_row.is_trigger_bit;

    let narrowed_ctx = ctx.narrow(&Step::AttributedBreakdownKey);
    let attributed_breakdown_key_bits = try_join_all(
        input_row
            .breakdown_key
            .iter()
            .zip(
                inputs_required_from_previous_row
                    .attributed_breakdown_key_bits
                    .iter(),
            )
            .enumerate()
            .map(|(i, (bd_key_bit, prev_row_attributed_bd_key_bit))| {
                let c = narrowed_ctx.narrow(&BitOpStep::from(i));
                async move {
                    let maybe_diff = input_row
                        .is_trigger_bit
                        .multiply(
                            &(prev_row_attributed_bd_key_bit.clone() - bd_key_bit),
                            c,
                            record_id,
                        )
                        .await?;
                    Ok::<_, Error>(maybe_diff + bd_key_bit)
                }
            }),
    )
    .await?;

    let did_trigger_get_attributed = input_row
        .is_trigger_bit
        .multiply(
            &ever_encountered_a_source_event,
            ctx.narrow(&Step::DidTriggerGetAttributed),
            record_id,
        )
        .await?;

    let narrowed_ctx = ctx.narrow(&Step::AttributedTriggerValue);
    let attributed_trigger_value = try_join_all(
        input_row
            .trigger_value
            .iter()
            .zip(repeat(did_trigger_get_attributed.clone()))
            .enumerate()
            .map(|(i, (trigger_value_bit, did_trigger_get_attributed))| {
                let c = narrowed_ctx.narrow(&BitOpStep::from(i));
                async move {
                    trigger_value_bit
                        .multiply(&did_trigger_get_attributed, c, record_id)
                        .await
                }
            }),
    )
    .await?;
    let (saturating_sum, is_saturated) = compute_saturating_sum(
        ctx.narrow(&Step::ComputeSaturatingSum),
        record_id,
        &attributed_trigger_value,
        &inputs_required_from_previous_row.saturating_sum,
        &inputs_required_from_previous_row.is_saturated,
        num_trigger_value_bits,
        num_saturating_sum_bits,
    )
    .await?;

    // TODO: compute is_saturated_and_prev_row_not_saturated and difference_to_cap in parallel
    let is_saturated_and_prev_row_not_saturated = is_saturated
        .multiply(
            &(share_of_one - &inputs_required_from_previous_row.is_saturated),
            ctx.narrow(&Step::IsSaturatedAndPrevRowNotSaturated),
            record_id,
        )
        .await?;
    let difference_to_cap = compute_truncated_difference_to_cap(
        ctx.narrow(&Step::ComputeDifferenceToCap),
        record_id,
        &saturating_sum,
        num_trigger_value_bits,
        num_saturating_sum_bits,
    )
    .await?;
    let narrowed_ctx1 = ctx.narrow(&Step::ComputedCappedAttributedTriggerValueNotSaturatedCase);
    let narrowed_ctx2 = ctx.narrow(&Step::ComputedCappedAttributedTriggerValueJustSaturatedCase);
    let capped_attributed_trigger_value = try_join_all(
        attributed_trigger_value
            .iter()
            .zip(inputs_required_from_previous_row.difference_to_cap.iter())
            .zip(repeat(is_saturated.clone()))
            .zip(repeat(is_saturated_and_prev_row_not_saturated))
            .enumerate()
            .map(
                |(
                    i,
                    (
                        ((attributed_tv_bit, prev_row_diff_to_cap_bit), is_saturated),
                        is_saturated_and_prev_row_not_saturated,
                    ),
                )| {
                    let c1 = narrowed_ctx1.narrow(&BitOpStep::from(i));
                    let c2 = narrowed_ctx2.narrow(&BitOpStep::from(i));
                    async move {
                        let not_saturated_case = (SB::share_known_value(&c1, Gf2::ONE)
                            - &is_saturated)
                            .multiply(attributed_tv_bit, c1, record_id)
                            .await?;
                        let just_saturated_case = is_saturated_and_prev_row_not_saturated
                            .multiply(&prev_row_diff_to_cap_bit, c2, record_id)
                            .await?;
                        Ok::<_, Error>(not_saturated_case + &just_saturated_case)
                    }
                },
            ),
    )
    .await?;

    let inputs_required_for_next_row = InputsRequiredFromPrevRow {
        ever_encountered_a_source_event,
        attributed_breakdown_key_bits: attributed_breakdown_key_bits.clone(),
        saturating_sum,
        is_saturated,
        difference_to_cap,
    };
    let outputs_for_aggregation = CappedAttributionOutputs {
        did_trigger_get_attributed,
        attributed_breakdown_key_bits,
        capped_attributed_trigger_value,
    };
    Ok((inputs_required_for_next_row, outputs_for_aggregation))
}
