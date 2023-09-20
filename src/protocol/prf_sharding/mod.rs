use std::iter::repeat;

use futures_util::future::try_join_all;
use ipa_macros::step;
use strum::AsRefStr;

use super::step::BitOpStep;
use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        context::{Context, UpgradableContext, UpgradedContext, Validator},
        BasicProtocols, RecordId,
    },
    repeat64str,
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, Linear as LinearSecretSharing,
    },
};

pub struct PrfShardedIpaInputRow<BK: GaloisField, TV: GaloisField> {
    prf_of_match_key: u64,
    is_trigger_bit: Replicated<Gf2>,
    breakdown_key: Replicated<BK>,
    trigger_value: Replicated<TV>,
}

struct InputsRequiredFromPrevRow {
    ever_encountered_a_source_event: Replicated<Gf2>,
    attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    saturating_sum: BitDecomposed<Replicated<Gf2>>,
    is_saturated: Replicated<Gf2>,
    difference_to_cap: BitDecomposed<Replicated<Gf2>>,
}

#[derive(Debug)]
pub struct CappedAttributionOutputs {
    did_trigger_get_attributed: Replicated<Gf2>,
    attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    capped_attributed_trigger_value: BitDecomposed<Replicated<Gf2>>,
}

#[derive(PartialEq, Eq, Debug)]
pub(crate) enum Step {
    BinaryValidator,
    EverEncounteredSourceEvent(usize),
    DidTriggerGetAttributed(usize),
    AttributedBreakdownKey(usize),
    AttributedTriggerValue(usize),
    ComputeSaturatingSum(usize),
    IsSaturatedAndPrevRowNotSaturated(usize),
    ComputeDifferenceToCap(usize),
    ComputedCappedAttributedTriggerValueNotSaturatedCase(usize),
    ComputedCappedAttributedTriggerValueJustSaturatedCase(usize),
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        const EVER_ENCOUNTERED_SOURCE_EVENT: [&str; 64] = repeat64str!["eese_row"];
        const DID_TRIGGER_GET_ATTRIBUTED: [&str; 64] = repeat64str!["dtga_row"];
        const ATTRIBUTED_BREAKDOWN_KEY: [&str; 64] = repeat64str!["abk_row"];
        const ATTRIBUTED_TRIGGER_VALUE: [&str; 64] = repeat64str!["atv_row"];
        const COMPUTE_SATURATING_SUM: [&str; 64] = repeat64str!["css_row"];
        const IS_SATURATED_AND_PREV_ROW_NOT_SATURATED: [&str; 64] = repeat64str!["isaprns_row"];
        const COMPUTE_DIFFERENCE_TO_CAP: [&str; 64] = repeat64str!["cdtc_row"];
        const COMPUTE_CAPPED_ATTRIBUTED_TRIGGER_VALUE_NOT_SATURATED_CASE: [&str; 64] =
            repeat64str!["ccatvnsc_row"];
        const COMPUTE_CAPPED_ATTRIBUTED_TRIGGER_VALUE_JUST_SATURATED_CASE: [&str; 64] =
            repeat64str!["ccatvjsc_row"];
        match self {
            Self::BinaryValidator => "binary_validator",
            Self::EverEncounteredSourceEvent(i) => EVER_ENCOUNTERED_SOURCE_EVENT[*i],
            Self::DidTriggerGetAttributed(i) => DID_TRIGGER_GET_ATTRIBUTED[*i],
            Self::AttributedBreakdownKey(i) => ATTRIBUTED_BREAKDOWN_KEY[*i],
            Self::AttributedTriggerValue(i) => ATTRIBUTED_TRIGGER_VALUE[*i],
            Self::ComputeSaturatingSum(i) => COMPUTE_SATURATING_SUM[*i],
            Self::IsSaturatedAndPrevRowNotSaturated(i) => {
                IS_SATURATED_AND_PREV_ROW_NOT_SATURATED[*i]
            }
            Self::ComputeDifferenceToCap(i) => COMPUTE_DIFFERENCE_TO_CAP[*i],
            Self::ComputedCappedAttributedTriggerValueNotSaturatedCase(i) => {
                COMPUTE_CAPPED_ATTRIBUTED_TRIGGER_VALUE_NOT_SATURATED_CASE[*i]
            }
            Self::ComputedCappedAttributedTriggerValueJustSaturatedCase(i) => {
                COMPUTE_CAPPED_ATTRIBUTED_TRIGGER_VALUE_JUST_SATURATED_CASE[*i]
            }
        }
    }
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
pub async fn attribution_and_capping<C, BK, TV>(
    sh_ctx: C,
    input_rows: &[PrfShardedIpaInputRow<BK, TV>],
    num_breakdown_key_bits: usize,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<Vec<CappedAttributionOutputs>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
{
    assert!(num_saturating_sum_bits > num_trigger_value_bits);
    assert!(num_trigger_value_bits > 0);
    assert!(num_breakdown_key_bits > 0);

    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    // TODO: fix num total records to be not a hard-coded constant, but variable per step
    // based on the histogram of how many users have how many records a piece
    let binary_m_ctx = binary_validator.context().set_total_records(1);

    let mut output = vec![];

    assert!(!input_rows.is_empty());
    let first_row = &input_rows[0];
    let mut prev_prf = first_row.prf_of_match_key;
    let mut prev_row_inputs = initialize_new_device_attribution_variables(
        Replicated::share_known_value(&binary_m_ctx, Gf2::ONE),
        first_row,
        num_breakdown_key_bits,
        num_trigger_value_bits,
        num_saturating_sum_bits,
    );
    let mut i: usize = 1;
    let mut num_users_encountered = 0;
    let mut row_for_user = 0;
    while i < input_rows.len() {
        let cur_row = &input_rows[i];
        if prev_prf == cur_row.prf_of_match_key {
            // Do some actual computation
            let (inputs_required_for_next_row, capped_attribution_outputs) =
                compute_row_with_previous(
                    binary_m_ctx.clone(),
                    RecordId(num_users_encountered),
                    row_for_user,
                    cur_row,
                    &prev_row_inputs,
                    num_breakdown_key_bits,
                    num_trigger_value_bits,
                    num_saturating_sum_bits,
                )
                .await?;
            output.push(capped_attribution_outputs);
            prev_row_inputs = inputs_required_for_next_row;

            row_for_user += 1;
        } else {
            prev_prf = cur_row.prf_of_match_key;
            prev_row_inputs = initialize_new_device_attribution_variables(
                Replicated::share_known_value(&binary_m_ctx, Gf2::ONE),
                cur_row,
                num_breakdown_key_bits,
                num_trigger_value_bits,
                num_saturating_sum_bits,
            );
            row_for_user = 0;
            num_users_encountered += 1;
        }
        i += 1;
    }

    Ok(output)
}

fn initialize_new_device_attribution_variables<BK, TV>(
    share_of_one: Replicated<Gf2>,
    input_row: &PrfShardedIpaInputRow<BK, TV>,
    num_breakdown_key_bits: usize,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> InputsRequiredFromPrevRow
where
    BK: GaloisField,
    TV: GaloisField,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_source_event: share_of_one - &input_row.is_trigger_bit,
        attributed_breakdown_key_bits: BitDecomposed::decompose(num_breakdown_key_bits, |i| {
            Replicated::new(
                Gf2::truncate_from(input_row.breakdown_key.left()[i]),
                Gf2::truncate_from(input_row.breakdown_key.right()[i]),
            )
        }),
        saturating_sum: BitDecomposed::new(vec![Replicated::ZERO; num_saturating_sum_bits]),
        is_saturated: Replicated::ZERO,
        // This is incorrect in the case that the CAP is less than the maximum value of "trigger value" for a single row
        // Not a problem if you assume that's an invalid input
        difference_to_cap: BitDecomposed::new(vec![Replicated::ZERO; num_trigger_value_bits]),
    }
}

///
/// Returns (`sum_bit`, `carry_out`)
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
    cur_value: &BitDecomposed<SB>,
    prev_sum: &BitDecomposed<SB>,
    prev_is_saturated: &SB,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<(BitDecomposed<SB>, SB), Error>
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
    Ok((BitDecomposed::new(output), updated_is_saturated))
}

///
/// Returns (`difference_bit`, `carry_out`)
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
/// There's also no reason to compute the `carry_out` for the final bit since it will go unused
///
async fn compute_truncated_difference_to_cap<C, SB>(
    ctx: C,
    record_id: RecordId,
    cur_sum: &BitDecomposed<SB>,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<BitDecomposed<SB>, Error>
where
    C: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C, Gf2>,
{
    assert!(cur_sum.len() == num_saturating_sum_bits);

    let mut carry_in = SB::share_known_value(&ctx, Gf2::ONE);
    let mut output = vec![];
    for (i, bit) in cur_sum.iter().enumerate().take(num_trigger_value_bits) {
        let c = ctx.narrow(&BitOpStep::from(i));
        let (difference_bit, carry_out) =
            one_bit_subtractor(c, record_id, &SB::ZERO, bit, &carry_in).await?;

        output.push(difference_bit);
        carry_in = carry_out;
    }
    Ok(BitDecomposed::new(output))
}

#[allow(clippy::too_many_lines)]
async fn compute_row_with_previous<C, BK, TV>(
    ctx: C,
    record_id: RecordId,
    row_for_user: usize,
    input_row: &PrfShardedIpaInputRow<BK, TV>,
    inputs_required_from_previous_row: &InputsRequiredFromPrevRow,
    num_breakdown_key_bits: usize,
    num_trigger_value_bits: usize,
    num_saturating_sum_bits: usize,
) -> Result<(InputsRequiredFromPrevRow, CappedAttributionOutputs), Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
{
    let bd_key = BitDecomposed::decompose(num_breakdown_key_bits, |i| {
        Replicated::new(
            Gf2::truncate_from(input_row.breakdown_key.left()[i]),
            Gf2::truncate_from(input_row.breakdown_key.right()[i]),
        )
    });
    let tv = BitDecomposed::decompose(num_trigger_value_bits, |i| {
        Replicated::new(
            Gf2::truncate_from(input_row.trigger_value.left()[i]),
            Gf2::truncate_from(input_row.trigger_value.right()[i]),
        )
    });
    assert!(bd_key.len() == num_breakdown_key_bits);
    assert!(
        inputs_required_from_previous_row
            .attributed_breakdown_key_bits
            .len()
            == num_breakdown_key_bits
    );
    assert!(tv.len() == num_trigger_value_bits);
    assert!(inputs_required_from_previous_row.saturating_sum.len() == num_saturating_sum_bits);

    let share_of_one = Replicated::share_known_value(&ctx, Gf2::ONE);

    // TODO: compute ever_encountered_a_source_event and attributed_breakdown_key_bits in parallel
    let ever_encountered_a_source_event = input_row
        .is_trigger_bit
        .multiply(
            &inputs_required_from_previous_row.ever_encountered_a_source_event,
            ctx.narrow(&Step::EverEncounteredSourceEvent(row_for_user)),
            record_id,
        )
        .await?
        + &share_of_one
        - &input_row.is_trigger_bit;

    let narrowed_ctx = ctx.narrow(&Step::AttributedBreakdownKey(row_for_user));
    let attributed_breakdown_key_bits = BitDecomposed::new(
        try_join_all(
            bd_key
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
        .await?,
    );

    let did_trigger_get_attributed = input_row
        .is_trigger_bit
        .multiply(
            &ever_encountered_a_source_event,
            ctx.narrow(&Step::DidTriggerGetAttributed(row_for_user)),
            record_id,
        )
        .await?;

    let narrowed_ctx = ctx.narrow(&Step::AttributedTriggerValue(row_for_user));
    let attributed_trigger_value = BitDecomposed::new(
        try_join_all(
            tv.iter()
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
        .await?,
    );

    let (saturating_sum, is_saturated) = compute_saturating_sum(
        ctx.narrow(&Step::ComputeSaturatingSum(row_for_user)),
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
            ctx.narrow(&Step::IsSaturatedAndPrevRowNotSaturated(row_for_user)),
            record_id,
        )
        .await?;

    let difference_to_cap = BitDecomposed::new(
        compute_truncated_difference_to_cap(
            ctx.narrow(&Step::ComputeDifferenceToCap(row_for_user)),
            record_id,
            &saturating_sum,
            num_trigger_value_bits,
            num_saturating_sum_bits,
        )
        .await?,
    );

    let narrowed_ctx1 = ctx.narrow(&Step::ComputedCappedAttributedTriggerValueNotSaturatedCase(
        row_for_user,
    ));
    let narrowed_ctx2 =
        ctx.narrow(&Step::ComputedCappedAttributedTriggerValueJustSaturatedCase(row_for_user));
    let capped_attributed_trigger_value = BitDecomposed::new(
        try_join_all(
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
                            let not_saturated_case = (Replicated::share_known_value(&c1, Gf2::ONE)
                                - &is_saturated)
                                .multiply(attributed_tv_bit, c1, record_id)
                                .await?;
                            let just_saturated_case = is_saturated_and_prev_row_not_saturated
                                .multiply(prev_row_diff_to_cap_bit, c2, record_id)
                                .await?;
                            Ok::<_, Error>(not_saturated_case + &just_saturated_case)
                        }
                    },
                ),
        )
        .await?,
    );

    let inputs_required_for_next_row = InputsRequiredFromPrevRow {
        ever_encountered_a_source_event,
        attributed_breakdown_key_bits: BitDecomposed::new(attributed_breakdown_key_bits.clone()),
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

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use super::{attribution_and_capping, CappedAttributionOutputs, PrfShardedIpaInputRow};
    use crate::{
        ff::{Field, GaloisField, Gf2, Gf8Bit},
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, IntoShares,
            SharedValue,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<BK: GaloisField, TV: GaloisField> {
        prf_of_match_key: u64,
        is_trigger_bit: Gf2,
        breakdown_key: BK,
        trigger_value: TV,
    }

    #[derive(Debug, PartialEq)]
    struct PreAggregationTestOutput {
        attributed_breakdown_key: u128,
        capped_attributed_trigger_value: u128,
    }

    impl<BK, TV> IntoShares<PrfShardedIpaInputRow<BK, TV>> for PreShardedAndSortedOPRFTestInput<BK, TV>
    where
        BK: GaloisField + IntoShares<Replicated<BK>>,
        TV: GaloisField + IntoShares<Replicated<TV>>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [PrfShardedIpaInputRow<BK, TV>; 3] {
            let PreShardedAndSortedOPRFTestInput {
                prf_of_match_key,
                is_trigger_bit,
                breakdown_key,
                trigger_value,
            } = self;

            let [is_trigger_bit0, is_trigger_bit1, is_trigger_bit2] =
                is_trigger_bit.share_with(rng);
            let [breakdown_key0, breakdown_key1, breakdown_key2] = breakdown_key.share_with(rng);
            let [trigger_value0, trigger_value1, trigger_value2] = trigger_value.share_with(rng);

            [
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit0,
                    breakdown_key: breakdown_key0,
                    trigger_value: trigger_value0,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit1,
                    breakdown_key: breakdown_key1,
                    trigger_value: trigger_value1,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit2,
                    breakdown_key: breakdown_key2,
                    trigger_value: trigger_value2,
                },
            ]
        }
    }

    impl Reconstruct<PreAggregationTestOutput> for [&CappedAttributionOutputs; 3] {
        fn reconstruct(&self) -> PreAggregationTestOutput {
            let [s0, s1, s2] = self;

            let attributed_breakdown_key_bits: BitDecomposed<Gf2> = BitDecomposed::new(
                s0.attributed_breakdown_key_bits
                    .iter()
                    .zip(s1.attributed_breakdown_key_bits.iter())
                    .zip(s2.attributed_breakdown_key_bits.iter())
                    .map(|((a, b), c)| [a, b, c].reconstruct()),
            );

            let capped_attributed_trigger_value_bits: BitDecomposed<Gf2> = BitDecomposed::new(
                s0.capped_attributed_trigger_value
                    .iter()
                    .zip(s1.capped_attributed_trigger_value.iter())
                    .zip(s2.capped_attributed_trigger_value.iter())
                    .map(|((a, b), c)| [a, b, c].reconstruct()),
            );

            PreAggregationTestOutput {
                attributed_breakdown_key: attributed_breakdown_key_bits
                    .iter()
                    .map(|x| x.as_u128())
                    .enumerate()
                    .fold(0_u128, |acc, (i, x)| acc + (x << i)),
                capped_attributed_trigger_value: capped_attributed_trigger_value_bits
                    .iter()
                    .map(|x| x.as_u128())
                    .enumerate()
                    .fold(0_u128, |acc, (i, x)| acc + (x << i)),
            }
        }
    }

    #[test]
    fn semi_honest() {
        const EXPECTED: &[PreAggregationTestOutput] = &[
            PreAggregationTestOutput {
                attributed_breakdown_key: 17,
                capped_attributed_trigger_value: 7,
            },
            PreAggregationTestOutput {
                attributed_breakdown_key: 20,
                capped_attributed_trigger_value: 0,
            },
            PreAggregationTestOutput {
                attributed_breakdown_key: 20,
                capped_attributed_trigger_value: 3,
            },
        ];
        const NUM_BREAKDOWN_KEY_BITS: usize = 5;
        const NUM_TRIGGER_VALUE_BITS: usize = 3;
        const NUM_SATURATING_SUM_BITS: usize = 5;

        run(|| async {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf8Bit, Gf8Bit>> = vec![
                PreShardedAndSortedOPRFTestInput {
                    prf_of_match_key: 123,
                    is_trigger_bit: Gf2::ZERO,
                    breakdown_key: Gf8Bit::truncate_from(17_u8),
                    trigger_value: Gf8Bit::truncate_from(0_u8),
                },
                PreShardedAndSortedOPRFTestInput {
                    prf_of_match_key: 123,
                    is_trigger_bit: Gf2::ONE,
                    breakdown_key: Gf8Bit::truncate_from(0_u8),
                    trigger_value: Gf8Bit::truncate_from(7_u8),
                },
                PreShardedAndSortedOPRFTestInput {
                    prf_of_match_key: 123,
                    is_trigger_bit: Gf2::ZERO,
                    breakdown_key: Gf8Bit::truncate_from(20_u8),
                    trigger_value: Gf8Bit::truncate_from(0_u8),
                },
                PreShardedAndSortedOPRFTestInput {
                    prf_of_match_key: 123,
                    is_trigger_bit: Gf2::ONE,
                    breakdown_key: Gf8Bit::truncate_from(0_u8),
                    trigger_value: Gf8Bit::truncate_from(3_u8),
                },
            ];

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    attribution_and_capping(
                        ctx,
                        input_rows.as_slice(),
                        NUM_BREAKDOWN_KEY_BITS,
                        NUM_TRIGGER_VALUE_BITS,
                        NUM_SATURATING_SUM_BITS,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, EXPECTED);
        });
    }
}
