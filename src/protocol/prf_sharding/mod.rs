use std::iter::repeat;

use futures_util::future::try_join;
use ipa_macros::Step;

use super::{boolean::saturating_sum::SaturatingSum, step::BitOpStep};
use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        boolean::or::or,
        context::{UpgradableContext, UpgradedContext, Validator},
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed,
    },
    seq_join::seq_try_join_all,
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
    saturating_sum: SaturatingSum<Replicated<Gf2>>,
    difference_to_cap: BitDecomposed<Replicated<Gf2>>,
}

#[derive(Debug)]
pub struct CappedAttributionOutputs {
    pub did_trigger_get_attributed: Replicated<Gf2>,
    pub attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    pub capped_attributed_trigger_value: BitDecomposed<Replicated<Gf2>>,
}

#[derive(Step)]
pub enum UserNthRowStep {
    #[dynamic]
    Row(usize),
}

impl From<usize> for UserNthRowStep {
    fn from(v: usize) -> Self {
        Self::Row(v)
    }
}

#[derive(Step)]
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

fn compute_histogram_of_users_with_row_count<S>(rows_chunked_by_user: &[Vec<S>]) -> Vec<usize> {
    let mut output = vec![];
    for user_rows in rows_chunked_by_user {
        for j in 0..user_rows.len() {
            if j >= output.len() {
                output.push(0);
            }
            output[j] += 1;
        }
    }
    output
}

fn set_up_contexts<C>(root_ctx: &C, histogram: &[usize]) -> Vec<C>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    let mut context_per_row_depth = Vec::with_capacity(histogram.len());
    for (row_number, num_users_having_that_row_number) in histogram.iter().enumerate() {
        if row_number == 0 {
            // no multiplications needed for each user's row 0. No context needed
        } else {
            let ctx_for_row_number = root_ctx
                .narrow(&UserNthRowStep::from(row_number))
                .set_total_records(*num_users_having_that_row_number);
            context_per_row_depth.push(ctx_for_row_number);
        }
    }
    context_per_row_depth
}

fn chunk_rows_by_user<BK, TV>(
    input_rows: Vec<PrfShardedIpaInputRow<BK, TV>>,
) -> Vec<Vec<PrfShardedIpaInputRow<BK, TV>>>
where
    BK: GaloisField,
    TV: GaloisField,
{
    let mut rows_for_user: Vec<PrfShardedIpaInputRow<BK, TV>> = vec![];

    let mut rows_chunked_by_user = vec![];
    for row in input_rows {
        if rows_for_user.is_empty() || row.prf_of_match_key == rows_for_user[0].prf_of_match_key {
            rows_for_user.push(row);
        } else {
            rows_chunked_by_user.push(rows_for_user);
            rows_for_user = vec![row];
        }
    }
    if !rows_for_user.is_empty() {
        rows_chunked_by_user.push(rows_for_user);
    }

    rows_chunked_by_user
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
    input_rows: Vec<PrfShardedIpaInputRow<BK, TV>>,
    num_saturating_sum_bits: usize,
) -> Result<Vec<CappedAttributionOutputs>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
{
    assert!(num_saturating_sum_bits > TV::BITS as usize);
    assert!(TV::BITS > 0);
    assert!(BK::BITS > 0);

    let rows_chunked_by_user = chunk_rows_by_user(input_rows);
    let histogram = compute_histogram_of_users_with_row_count(&rows_chunked_by_user);
    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();
    let mut num_users_who_encountered_row_depth = Vec::with_capacity(histogram.len());
    let ctx_for_row_number = set_up_contexts(&binary_m_ctx, &histogram);
    let mut futures = Vec::with_capacity(rows_chunked_by_user.len());
    for rows_for_user in rows_chunked_by_user {
        for i in 0..rows_for_user.len() {
            if i >= num_users_who_encountered_row_depth.len() {
                num_users_who_encountered_row_depth.push(0);
            }
            num_users_who_encountered_row_depth[i] += 1;
        }

        futures.push(evaluate_per_user_attribution_circuit(
            &ctx_for_row_number,
            num_users_who_encountered_row_depth
                .iter()
                .take(rows_for_user.len())
                .map(|x| RecordId(x - 1))
                .collect(),
            rows_for_user,
            num_saturating_sum_bits,
        ));
    }
    let outputs_chunked_by_user = seq_try_join_all(sh_ctx.active_work(), futures).await?;
    Ok(outputs_chunked_by_user
        .into_iter()
        .flatten()
        .collect::<Vec<CappedAttributionOutputs>>())
}

async fn evaluate_per_user_attribution_circuit<C, BK, TV>(
    ctx_for_row_number: &[C],
    record_id_for_each_depth: Vec<RecordId>,
    rows_for_user: Vec<PrfShardedIpaInputRow<BK, TV>>,
    num_saturating_sum_bits: usize,
) -> Result<Vec<CappedAttributionOutputs>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
{
    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(vec![]);
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs = initialize_new_device_attribution_variables(
        Replicated::share_known_value(&ctx_for_row_number[0], Gf2::ONE),
        first_row,
        num_saturating_sum_bits,
    );

    let mut output = Vec::with_capacity(rows_for_user.len() - 1);
    for (i, row) in rows_for_user.iter().skip(1).enumerate() {
        let ctx_for_this_row_depth = ctx_for_row_number[i].clone(); // no context was created for row 0
        let record_id_for_this_row_depth = record_id_for_each_depth[i + 1]; // skip row 0

        let capped_attribution_outputs = compute_row_with_previous(
            ctx_for_this_row_depth,
            record_id_for_this_row_depth,
            row,
            &mut prev_row_inputs,
            num_saturating_sum_bits,
        )
        .await?;

        output.push(capped_attribution_outputs);
    }

    Ok(output)
}

///
/// Upon encountering the first row of data from a new user (as distinguished by a different OPRF of the match key)
/// this function encapsulates the variables that must be initialized. No communication is required for this first row.
///
fn initialize_new_device_attribution_variables<BK, TV>(
    share_of_one: Replicated<Gf2>,
    input_row: &PrfShardedIpaInputRow<BK, TV>,
    num_saturating_sum_bits: usize,
) -> InputsRequiredFromPrevRow
where
    BK: GaloisField,
    TV: GaloisField,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_source_event: share_of_one - &input_row.is_trigger_bit,
        attributed_breakdown_key_bits: BitDecomposed::decompose(BK::BITS, |i| {
            input_row.breakdown_key.map(|v| Gf2::truncate_from(v[i]))
        }),
        saturating_sum: SaturatingSum::new(
            BitDecomposed::new(vec![Replicated::ZERO; num_saturating_sum_bits]),
            Replicated::ZERO,
        ),
        // This is incorrect in the case that the CAP is less than the maximum value of "trigger value" for a single row
        // Not a problem if you assume that's an invalid input
        difference_to_cap: BitDecomposed::new(vec![Replicated::ZERO; TV::BITS as usize]),
    }
}

///
/// To support "Last Touch Attribution" we move the `breakdown_key` of the most recent source event
/// down to all of trigger events that follow it.
///
/// The logic here is extremely simple. For each row:
/// (a) if it is a source event, take the breakdown key bits.
/// (b) if it is a trigger event, take the breakdown key bits from the preceding line
///
async fn breakdown_key_of_most_recent_source_event<C>(
    ctx: C,
    record_id: RecordId,
    is_trigger_bit: &Replicated<Gf2>,
    prev_row_breakdown_key_bits: &BitDecomposed<Replicated<Gf2>>,
    cur_row_breakdown_key_bits: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    Ok(BitDecomposed::new(
        ctx.parallel_join(
            cur_row_breakdown_key_bits
                .iter()
                .zip(prev_row_breakdown_key_bits.iter())
                .enumerate()
                .map(|(i, (cur_bit, prev_bit))| {
                    let c = ctx.narrow(&BitOpStep::from(i));
                    async move {
                        let maybe_diff = is_trigger_bit
                            .multiply(&(prev_bit.clone() - cur_bit), c, record_id)
                            .await?;
                        Ok::<_, Error>(maybe_diff + cur_bit)
                    }
                }),
        )
        .await?,
    ))
}

///
/// In this simple "Last Touch Attribution" model, the `trigger_value` of a trigger event is either
/// (a) Attributed to a single `breakdown_key`
/// (b) Not attributed, and thus zeroed out
///
/// The logic here is extremely simple. There is a secret-shared bit indicating if a given row is an "attributed trigger event"
/// The bits of the `trigger_value` are all multiplied by this bit in order to zero out contributions from unattributed trigger events
///
async fn zero_out_trigger_value_unless_attributed<C>(
    ctx: C,
    record_id: RecordId,
    did_trigger_get_attributed: &Replicated<Gf2>,
    trigger_value: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    Ok(BitDecomposed::new(
        ctx.parallel_join(
            trigger_value
                .iter()
                .zip(repeat(did_trigger_get_attributed))
                .enumerate()
                .map(|(i, (trigger_value_bit, did_trigger_get_attributed))| {
                    let c = ctx.narrow(&BitOpStep::from(i));
                    async move {
                        trigger_value_bit
                            .multiply(did_trigger_get_attributed, c, record_id)
                            .await
                    }
                }),
        )
        .await?,
    ))
}

///
/// To provide a differential privacy guarantee, we need to bound the maximum contribution from any given user to some cap.
///
/// The following values are computed for each row:
/// (1) The uncapped "Attributed trigger value" (which is either the original `trigger_value` bits or zero if it was unattributed)
/// (2) The cumulative sum of "Attributed trigger value" thus far (which "saturates" at a given power of two as indicated by the `is_saturated` flag)
/// (3) The "delta to cap", which is the difference between the "cap" and the cumulative sum (this value is meaningless once the cumulative sum is saturated)
///
/// To perfectly cap each user's contributions at precisely the cap, the "attributed trigger value" will sometimes need to be lowered,
/// such that the total cumulative sum adds up to exactly the cap.
///
/// This oblivious algorithm computes the "capped attributed trigger value" in the following way:
/// IF the cumulative is NOT YET saturated:
///     - just return the attributed trigger value
/// ELSE IF the cumulative sum JUST became saturated (that is, it was NOT saturated on the preceding line but IS on this line):
///     - return the "delta to cap" from the preceding line
/// ELSE
///     - return zero
///
async fn compute_capped_trigger_value<C>(
    ctx: C,
    record_id: RecordId,
    is_saturated: &Replicated<Gf2>,
    is_saturated_and_prev_row_not_saturated: &Replicated<Gf2>,
    prev_row_diff_to_cap: &BitDecomposed<Replicated<Gf2>>,
    attributed_trigger_value: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    let narrowed_ctx1 = ctx.narrow(&Step::ComputedCappedAttributedTriggerValueNotSaturatedCase);
    let narrowed_ctx2 = ctx.narrow(&Step::ComputedCappedAttributedTriggerValueJustSaturatedCase);

    let one = &Replicated::share_known_value(&narrowed_ctx1, Gf2::ONE);

    Ok(BitDecomposed::new(
        ctx.parallel_join(
            attributed_trigger_value
                .iter()
                .zip(prev_row_diff_to_cap.iter())
                .enumerate()
                .map(|(i, (bit, prev_bit))| {
                    let c1 = narrowed_ctx1.narrow(&BitOpStep::from(i));
                    let c2 = narrowed_ctx2.narrow(&BitOpStep::from(i));
                    async move {
                        let not_saturated_case =
                            (one - is_saturated).multiply(bit, c1, record_id).await?;
                        let just_saturated_case = is_saturated_and_prev_row_not_saturated
                            .multiply(prev_bit, c2, record_id)
                            .await?;
                        Ok::<_, Error>(not_saturated_case + &just_saturated_case)
                    }
                }),
        )
        .await?,
    ))
}

///
/// This function contains the main logic for the per-user attribution circuit.
/// Multiple rows of data about a single user are processed in-order from oldest to newest.
///
/// Summary:
/// - Last touch attribution
///     - Every trigger event which is preceded by a source event is attributed
///     - Trigger events are attributed to the `breakdown_key` of the most recent preceding source event
/// - Per user capping
///     - A cumulative sum of "Attributed Trigger Value" is maintained
///     - Bitwise addition is used, and a single bit indicates if the sum is "saturated"
///     - The only available values for "cap" are powers of 2 (i.e. 1, 2, 4, 8, 16, 32, ...)
///     - Prior to the cumulative sum reaching saturation, attributed trigger values are passed along
///     - The row which puts the cumulative sum over the cap is "capped" to the delta between the cumulative sum of the last row and the cap
///     - All subsequent rows contribute zero
/// - Outputs
///     - If a user has `N` input rows, they will generate `N-1` output rows. (The first row cannot possibly contribute any value to the output)
///     - Each output row has two main values:
///         - `capped_attributed_trigger_value` - the value to contribute to the output (bitwise secret-shared),
///         - `attributed_breakdown_key` - the breakdown to which this contribution applies (bitwise secret-shared),
///     - Additional output:
///         - `did_trigger_get_attributed` - a secret-shared bit indicating if this row corresponds to a trigger event
///           which was attributed. Might be able to reveal this (after a shuffle and the addition of dummies) to minimize
///           the amount of processing work that must be done in the Aggregation stage.
async fn compute_row_with_previous<C, BK, TV>(
    ctx: C,
    record_id: RecordId,
    input_row: &PrfShardedIpaInputRow<BK, TV>,
    inputs_required_from_previous_row: &mut InputsRequiredFromPrevRow,
    num_saturating_sum_bits: usize,
) -> Result<CappedAttributionOutputs, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
{
    let bd_key = BitDecomposed::decompose(BK::BITS, |i| {
        input_row.breakdown_key.map(|v| Gf2::truncate_from(v[i]))
    });
    let tv = BitDecomposed::decompose(TV::BITS, |i| {
        input_row.trigger_value.map(|v| Gf2::truncate_from(v[i]))
    });
    assert_eq!(
        inputs_required_from_previous_row.saturating_sum.sum.len(),
        num_saturating_sum_bits
    );

    let share_of_one = Replicated::share_known_value(&ctx, Gf2::ONE);
    let is_source_event = &share_of_one - &input_row.is_trigger_bit;

    let (ever_encountered_a_source_event, attributed_breakdown_key_bits) = try_join(
        or(
            ctx.narrow(&Step::EverEncounteredSourceEvent),
            record_id,
            &is_source_event,
            &inputs_required_from_previous_row.ever_encountered_a_source_event,
        ),
        breakdown_key_of_most_recent_source_event(
            ctx.narrow(&Step::AttributedBreakdownKey),
            record_id,
            &input_row.is_trigger_bit,
            &inputs_required_from_previous_row.attributed_breakdown_key_bits,
            &bd_key,
        ),
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

    let attributed_trigger_value = zero_out_trigger_value_unless_attributed(
        ctx.narrow(&Step::AttributedTriggerValue),
        record_id,
        &did_trigger_get_attributed,
        &tv,
    )
    .await?;

    let updated_sum = inputs_required_from_previous_row
        .saturating_sum
        .add(
            ctx.narrow(&Step::ComputeSaturatingSum),
            record_id,
            &attributed_trigger_value,
        )
        .await?;

    let (is_saturated_and_prev_row_not_saturated, difference_to_cap) = try_join(
        updated_sum.is_saturated.multiply(
            &(share_of_one
                - &inputs_required_from_previous_row
                    .saturating_sum
                    .is_saturated),
            ctx.narrow(&Step::IsSaturatedAndPrevRowNotSaturated),
            record_id,
        ),
        updated_sum.truncated_delta_to_saturation_point(
            ctx.narrow(&Step::ComputeDifferenceToCap),
            record_id,
            TV::BITS,
        ),
    )
    .await?;

    let capped_attributed_trigger_value = compute_capped_trigger_value(
        ctx,
        record_id,
        &updated_sum.is_saturated,
        &is_saturated_and_prev_row_not_saturated,
        &inputs_required_from_previous_row.difference_to_cap,
        &attributed_trigger_value,
    )
    .await?;

    *inputs_required_from_previous_row = InputsRequiredFromPrevRow {
        ever_encountered_a_source_event,
        attributed_breakdown_key_bits: BitDecomposed::new(attributed_breakdown_key_bits.clone()),
        saturating_sum: updated_sum,
        difference_to_cap,
    };
    let outputs_for_aggregation = CappedAttributionOutputs {
        did_trigger_get_attributed,
        attributed_breakdown_key_bits,
        capped_attributed_trigger_value,
    };
    Ok(outputs_for_aggregation)
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use super::{attribution_and_capping, CappedAttributionOutputs, PrfShardedIpaInputRow};
    use crate::{
        ff::{Field, GaloisField, Gf2, Gf3Bit, Gf5Bit},
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

    fn test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        breakdown_key: u8,
        trigger_value: u8,
    ) -> PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit> {
        let is_trigger_bit = if is_trigger { Gf2::ONE } else { Gf2::ZERO };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            breakdown_key: Gf5Bit::truncate_from(breakdown_key),
            trigger_value: Gf3Bit::truncate_from(trigger_value),
        }
    }

    fn test_output(
        attributed_breakdown_key: u128,
        capped_attributed_trigger_value: u128,
    ) -> PreAggregationTestOutput {
        PreAggregationTestOutput {
            attributed_breakdown_key,
            capped_attributed_trigger_value,
        }
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
                    .map(Field::as_u128)
                    .enumerate()
                    .fold(0_u128, |acc, (i, x)| acc + (x << i)),
                capped_attributed_trigger_value: capped_attributed_trigger_value_bits
                    .iter()
                    .map(Field::as_u128)
                    .enumerate()
                    .fold(0_u128, |acc, (i, x)| acc + (x << i)),
            }
        }
    }

    #[test]
    fn semi_honest() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit>> = vec![
                /* First User */
                test_input(123, false, 17, 0),
                test_input(123, true, 0, 7),
                test_input(123, false, 20, 0),
                test_input(123, true, 0, 3),
                /* Second User */
                test_input(234, false, 12, 0),
                test_input(234, true, 0, 5),
                /* Third User */
                test_input(345, false, 20, 0),
                test_input(345, true, 0, 7),
                test_input(345, false, 18, 0),
                test_input(345, false, 12, 0),
                test_input(345, true, 0, 7),
                test_input(345, true, 0, 7),
                test_input(345, true, 0, 7),
                test_input(345, true, 0, 7),
            ];

            let expected: [PreAggregationTestOutput; 11] = [
                test_output(17, 7),
                test_output(20, 0),
                test_output(20, 3),
                test_output(12, 5),
                test_output(20, 7),
                test_output(18, 0),
                test_output(12, 0),
                test_output(12, 7),
                test_output(12, 7),
                test_output(12, 7),
                test_output(12, 4),
            ];
            let num_saturating_bits: usize = 5;

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    attribution_and_capping::<_, Gf5Bit, Gf3Bit>(
                        ctx,
                        input_rows,
                        num_saturating_bits,
                    )
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }
}
