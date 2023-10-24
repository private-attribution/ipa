use std::iter::{repeat, zip};

use futures::{stream::iter as stream_iter, TryStreamExt};
use futures_util::{future::try_join, StreamExt};
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    protocol::{
        basics::{if_else, SecureMul, ShareKnownValue},
        boolean::{or::or, saturating_sum::SaturatingSum},
        context::{UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::convert_bits,
        step::BitOpStep,
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        BitDecomposed, Linear as LinearSecretSharing, SharedValue,
    },
    seq_join::{seq_join, seq_try_join_all},
};

pub mod bucket;
#[cfg(feature = "descriptive-gate")]
pub mod feature_label_dot_product;

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

impl InputsRequiredFromPrevRow {
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
    pub async fn compute_row_with_previous<C, BK, TV>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<BK, TV>,
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
        assert_eq!(self.saturating_sum.sum.len(), num_saturating_sum_bits);

        let share_of_one = Replicated::share_known_value(&ctx, Gf2::ONE);
        let is_source_event = &share_of_one - &input_row.is_trigger_bit;

        let (ever_encountered_a_source_event, attributed_breakdown_key_bits) = try_join(
            or(
                ctx.narrow(&Step::EverEncounteredSourceEvent),
                record_id,
                &is_source_event,
                &self.ever_encountered_a_source_event,
            ),
            breakdown_key_of_most_recent_source_event(
                ctx.narrow(&Step::AttributedBreakdownKey),
                record_id,
                &input_row.is_trigger_bit,
                &self.attributed_breakdown_key_bits,
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

        let updated_sum = self
            .saturating_sum
            .add(
                ctx.narrow(&Step::ComputeSaturatingSum),
                record_id,
                &attributed_trigger_value,
            )
            .await?;

        let (is_saturated_and_prev_row_not_saturated, difference_to_cap) = try_join(
            updated_sum.is_saturated.multiply(
                &(share_of_one - &self.saturating_sum.is_saturated),
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
            &self.difference_to_cap,
            &attributed_trigger_value,
        )
        .await?;

        self.ever_encountered_a_source_event = ever_encountered_a_source_event;
        self.attributed_breakdown_key_bits = attributed_breakdown_key_bits.clone();
        self.saturating_sum = updated_sum;
        self.difference_to_cap = difference_to_cap;

        let outputs_for_aggregation = CappedAttributionOutputs {
            did_trigger_get_attributed,
            attributed_breakdown_key_bits,
            capped_attributed_trigger_value,
        };
        Ok(outputs_for_aggregation)
    }
}

#[derive(Debug)]
pub struct CappedAttributionOutputs {
    pub did_trigger_get_attributed: Replicated<Gf2>,
    pub attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    pub capped_attributed_trigger_value: BitDecomposed<Replicated<Gf2>>,
}

#[derive(Step)]
pub enum UserNthRowStep {
    #[dynamic(64)]
    Row(usize),
}

impl From<usize> for UserNthRowStep {
    fn from(v: usize) -> Self {
        Self::Row(v)
    }
}

#[derive(Step)]
pub enum BinaryTreeDepthStep {
    #[dynamic(64)]
    Depth(usize),
}

impl From<usize> for BinaryTreeDepthStep {
    fn from(v: usize) -> Self {
        Self::Depth(v)
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
    ModulusConvertBreakdownKeyBits,
    ModulusConvertConversionValueBits,
    MoveValueToCorrectBreakdown,
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
        return Ok(Vec::new());
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

        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(
                ctx_for_this_row_depth,
                record_id_for_this_row_depth,
                row,
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
                    async move { if_else(c, record_id, is_trigger_bit, prev_bit, cur_bit).await }
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

    let zero = &Replicated::share_known_value(&narrowed_ctx1, Gf2::ZERO);

    Ok(BitDecomposed::new(
        ctx.parallel_join(
            zip(attributed_trigger_value.iter(), prev_row_diff_to_cap.iter())
                .enumerate()
                .map(|(i, (bit, prev_bit))| {
                    let c1 = narrowed_ctx1.narrow(&BitOpStep::from(i));
                    let c2 = narrowed_ctx2.narrow(&BitOpStep::from(i));
                    async move {
                        let (not_saturated_case, just_saturated_case) = try_join(
                            if_else(c1, record_id, is_saturated, zero, bit),
                            if_else(
                                c2,
                                record_id,
                                is_saturated_and_prev_row_not_saturated,
                                prev_bit,
                                zero,
                            ),
                        )
                        .await?;
                        Ok::<_, Error>(not_saturated_case + &just_saturated_case)
                    }
                }),
        )
        .await?,
    ))
}

/// This circuit expects to receive records from multiple users,
/// but with all of the records from a given user adjacent to one another, and in time order.
///
/// This is a wrapper function to do attribution and capping per user followed by aggregating
/// the results per breakdown key
/// # Errors
/// If there is an issue in multiplication, it will error
pub async fn attribution_and_capping_and_aggregation<C, BK, TV, F, S, SB>(
    sh_ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<BK, TV>>,
    num_saturating_sum_bits: usize,
) -> Result<Vec<S>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable + SecureMul<C::UpgradedContext<F>>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    F: PrimeField + ExtendableField,
    TV: GaloisField,
    BK: GaloisField,
{
    let prime_field_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<F>();
    let prime_field_m_ctx = prime_field_validator.context();

    let user_level_attributions: Vec<CappedAttributionOutputs> =
        attribution_and_capping(sh_ctx, input_rows, num_saturating_sum_bits).await?;

    do_aggregation::<_, BK, TV, F, S>(prime_field_m_ctx, user_level_attributions).await
}

/// Sub-protocol of the PRF-sharded IPA Protocol
///
/// This function receives capped user level contributions to breakdown key buckets. It does the following
/// 1. Convert bit-shares of breakdown keys and conversion values from binary field to prime field
/// 2. Transform conversion value bits to additive sharing
/// 3. Move all conversion values to corresponding breakdown key bucket
///
/// At the end of the function, all conversions are aggregated and placed in the appropriate breakdown key bucket
async fn do_aggregation<C, BK, TV, F, S>(
    ctx: C,
    user_level_attributions: Vec<CappedAttributionOutputs>,
) -> Result<Vec<S>, Error>
where
    C: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable + SecureMul<C>,
    BK: GaloisField,
    TV: GaloisField,
    F: PrimeField + ExtendableField,
{
    let num_records = user_level_attributions.len();

    // in case no attributable conversion is found, return 0.
    // as anyways the helpers know that no attributions resulted.
    if num_records == 0 {
        return Ok(vec![S::ZERO; 1 << BK::BITS]);
    }

    let (bk_vec, tv_vec): (Vec<_>, Vec<_>) = user_level_attributions
        .into_iter()
        .map(|row| {
            (
                row.attributed_breakdown_key_bits,
                row.capped_attributed_trigger_value,
            )
        })
        .unzip();

    // modulus convert breakdown keys
    let converted_bks = convert_bits(
        ctx.narrow(&Step::ModulusConvertBreakdownKeyBits)
            .set_total_records(num_records),
        stream_iter(bk_vec),
        0..BK::BITS,
    );
    // modulus convert attributed value
    let converted_values = convert_bits(
        ctx.narrow(&Step::ModulusConvertConversionValueBits)
            .set_total_records(num_records),
        stream_iter(tv_vec),
        0..TV::BITS,
    );

    // tranform value bits to large field
    let large_field_values = converted_values
        .map(|val| BitDecomposed::to_additive_sharing_in_large_field_consuming(val.unwrap()));

    // move each value to the correct bucket
    let row_contributions_stream = converted_bks
        .zip(large_field_values)
        .zip(futures::stream::repeat(
            ctx.narrow(&Step::MoveValueToCorrectBreakdown)
                .set_total_records(num_records),
        ))
        .enumerate()
        .map(|(i, ((bk_bits, value), ctx))| {
            let record_id: RecordId = RecordId::from(i);
            let bd_key = bk_bits.unwrap();
            async move {
                bucket::move_single_value_to_bucket::<BK, _, _, _>(
                    ctx,
                    record_id,
                    bd_key,
                    value,
                    1 << BK::BITS,
                    false,
                )
                .await
            }
        });

    // aggregate all row level contributions
    let row_contributions = seq_join(ctx.active_work(), row_contributions_stream);
    row_contributions
        .try_fold(
            vec![S::ZERO; 1 << BK::BITS],
            |mut running_sums, row_contribution| async move {
                for (i, contribution) in row_contribution.iter().enumerate() {
                    running_sums[i] += contribution;
                }
                Ok(running_sums)
            },
        )
        .await
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use super::{attribution_and_capping, CappedAttributionOutputs, PrfShardedIpaInputRow};
    use crate::{
        ff::{Field, Fp32BitPrime, GaloisField, Gf2, Gf3Bit, Gf5Bit},
        protocol::{
            context::{UpgradableContext, Validator},
            prf_sharding::{attribution_and_capping_and_aggregation, do_aggregation},
        },
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, IntoShares,
            SharedValue,
        },
        test_executor::run,
        test_fixture::{get_bits, Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<BK: GaloisField, TV: GaloisField> {
        prf_of_match_key: u64,
        is_trigger_bit: Gf2,
        breakdown_key: BK,
        trigger_value: TV,
    }

    fn oprf_test_input(
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

    fn bitwise_bd_key_and_value<BK, TV>(
        attributed_breakdown_key: u128,
        capped_attributed_trigger_value: u128,
    ) -> PreAggregationTestInputInBits
    where
        BK: GaloisField,
        TV: GaloisField,
    {
        PreAggregationTestInputInBits {
            attributed_breakdown_key: get_bits::<Gf2>(
                attributed_breakdown_key.try_into().unwrap(),
                BK::BITS,
            ),
            capped_attributed_trigger_value: get_bits::<Gf2>(
                capped_attributed_trigger_value.try_into().unwrap(),
                TV::BITS,
            ),
        }
    }

    fn decimal_bd_key_and_value(
        attributed_breakdown_key: u128,
        capped_attributed_trigger_value: u128,
    ) -> PreAggregationTestOutputInDecimal {
        PreAggregationTestOutputInDecimal {
            attributed_breakdown_key,
            capped_attributed_trigger_value,
        }
    }

    #[derive(Debug, PartialEq)]
    struct PreAggregationTestOutputInDecimal {
        attributed_breakdown_key: u128,
        capped_attributed_trigger_value: u128,
    }

    #[derive(Debug, PartialEq)]
    struct PreAggregationTestInputInBits {
        attributed_breakdown_key: BitDecomposed<Gf2>,
        capped_attributed_trigger_value: BitDecomposed<Gf2>,
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

    impl IntoShares<CappedAttributionOutputs> for PreAggregationTestInputInBits {
        fn share_with<R: Rng>(self, rng: &mut R) -> [CappedAttributionOutputs; 3] {
            let PreAggregationTestInputInBits {
                attributed_breakdown_key,
                capped_attributed_trigger_value,
            } = self;

            let did_trigger_get_attributed = Gf2::ONE;
            let [attributed_breakdown_key0, attributed_breakdown_key1, attributed_breakdown_key2] =
                attributed_breakdown_key.share_with(rng);
            let [capped_attributed_trigger_value0, capped_attributed_trigger_value1, capped_attributed_trigger_value2] =
                capped_attributed_trigger_value.share_with(rng);
            let [did_trigger_get_attributed0, did_trigger_get_attributed1, did_trigger_get_attributed2] =
                did_trigger_get_attributed.share_with(rng);

            [
                CappedAttributionOutputs {
                    did_trigger_get_attributed: did_trigger_get_attributed0,
                    attributed_breakdown_key_bits: attributed_breakdown_key0,
                    capped_attributed_trigger_value: capped_attributed_trigger_value0,
                },
                CappedAttributionOutputs {
                    did_trigger_get_attributed: did_trigger_get_attributed1,
                    attributed_breakdown_key_bits: attributed_breakdown_key1,
                    capped_attributed_trigger_value: capped_attributed_trigger_value1,
                },
                CappedAttributionOutputs {
                    did_trigger_get_attributed: did_trigger_get_attributed2,
                    attributed_breakdown_key_bits: attributed_breakdown_key2,
                    capped_attributed_trigger_value: capped_attributed_trigger_value2,
                },
            ]
        }
    }

    impl Reconstruct<PreAggregationTestOutputInDecimal> for [&CappedAttributionOutputs; 3] {
        fn reconstruct(&self) -> PreAggregationTestOutputInDecimal {
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

            PreAggregationTestOutputInDecimal {
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
    fn semi_honest_attribution_and_capping() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit>> = vec![
                /* First User */
                oprf_test_input(123, false, 17, 0),
                oprf_test_input(123, true, 0, 7),
                oprf_test_input(123, false, 20, 0),
                oprf_test_input(123, true, 0, 3),
                /* Second User */
                oprf_test_input(234, false, 12, 0),
                oprf_test_input(234, true, 0, 5),
                /* Third User */
                oprf_test_input(345, false, 20, 0),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, false, 18, 0),
                oprf_test_input(345, false, 12, 0),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
            ];

            let expected: [PreAggregationTestOutputInDecimal; 11] = [
                decimal_bd_key_and_value(17, 7),
                decimal_bd_key_and_value(20, 0),
                decimal_bd_key_and_value(20, 3),
                decimal_bd_key_and_value(12, 5),
                decimal_bd_key_and_value(20, 7),
                decimal_bd_key_and_value(18, 0),
                decimal_bd_key_and_value(12, 0),
                decimal_bd_key_and_value(12, 7),
                decimal_bd_key_and_value(12, 7),
                decimal_bd_key_and_value(12, 7),
                decimal_bd_key_and_value(12, 4),
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

    #[test]
    fn semi_honest_aggregation_capping_attribution() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit>> = vec![
                /* First User */
                oprf_test_input(123, false, 17, 0),
                oprf_test_input(123, true, 0, 7),
                oprf_test_input(123, false, 20, 0),
                oprf_test_input(123, true, 0, 3),
                /* Second User */
                oprf_test_input(234, false, 12, 0),
                oprf_test_input(234, true, 0, 5),
                /* Third User */
                oprf_test_input(345, false, 20, 0),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, false, 18, 0),
                oprf_test_input(345, false, 12, 0),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
                oprf_test_input(345, true, 0, 7),
            ];

            let mut expected = [0_u128; 32];
            expected[12] = 30;
            expected[17] = 7;
            expected[20] = 10;

            let num_saturating_bits: usize = 5;

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    attribution_and_capping_and_aggregation::<
                        _,
                        Gf5Bit,
                        Gf3Bit,
                        Fp32BitPrime,
                        _,
                        Replicated<Gf2>,
                    >(ctx, input_rows, num_saturating_bits)
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }

    #[test]
    fn semi_honest_aggregation() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreAggregationTestInputInBits> = vec![
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(17, 7),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(20, 0),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(20, 3),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 5),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(20, 7),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(18, 0),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 0),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 7),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 7),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 7),
                bitwise_bd_key_and_value::<Gf5Bit, Gf3Bit>(12, 4),
            ];

            let mut expected = [0_u128; 32];
            expected[12] = 30;
            expected[17] = 7;
            expected[20] = 10;

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    let validator = ctx.validator();
                    let ctx = validator.context();
                    do_aggregation::<_, Gf5Bit, Gf3Bit, Fp32BitPrime, _>(ctx, input_rows)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }
}
