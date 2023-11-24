use std::{
    iter::{repeat, zip},
    num::NonZeroU32,
    pin::pin,
};

use futures::{stream::iter as stream_iter, TryStreamExt};
use futures_util::{
    future::{try_join, try_join3},
    stream::unfold,
    Stream, StreamExt,
};
use ipa_macros::Step;

use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    helpers::Role,
    protocol::{
        basics::{if_else, SecureMul, ShareKnownValue},
        boolean::{comparison::bitwise_less_than_constant, or::or, saturating_sum::SaturatingSum},
        context::{Context, UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::{convert_bits, BitConversionTriple, ToBitConversionTriples},
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
    seq_join::{seq_join, SeqJoin},
};

pub mod bucket;
#[cfg(feature = "descriptive-gate")]
pub mod feature_label_dot_product;

#[derive(Debug)]
pub struct PrfShardedIpaInputRow<BK: GaloisField, TV: GaloisField, TS: GaloisField> {
    pub prf_of_match_key: u64,
    pub is_trigger_bit: Replicated<Gf2>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
}

impl<BK: GaloisField, TS: GaloisField, TV: GaloisField> GroupingKey
    for PrfShardedIpaInputRow<BK, TV, TS>
{
    fn get_grouping_key(&self) -> u64 {
        self.prf_of_match_key
    }
}

impl<BK: GaloisField, TV: GaloisField, TS: GaloisField> PrfShardedIpaInputRow<BK, TV, TS> {
    pub fn breakdown_key_bits(&self) -> BitDecomposed<Replicated<Gf2>> {
        BitDecomposed::decompose(BK::BITS, |i| {
            self.breakdown_key.map(|v| Gf2::truncate_from(v[i]))
        })
    }

    pub fn trigger_value_bits(&self) -> BitDecomposed<Replicated<Gf2>> {
        BitDecomposed::decompose(TV::BITS, |i| {
            self.trigger_value.map(|v| Gf2::truncate_from(v[i]))
        })
    }

    pub fn timestamp_bits(&self) -> BitDecomposed<Replicated<Gf2>> {
        BitDecomposed::decompose(TS::BITS, |i| {
            self.timestamp.map(|v| Gf2::truncate_from(v[i]))
        })
    }
}

struct InputsRequiredFromPrevRow {
    ever_encountered_a_source_event: Replicated<Gf2>,
    attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    saturating_sum: SaturatingSum<Replicated<Gf2>>,
    difference_to_cap: BitDecomposed<Replicated<Gf2>>,
    source_event_timestamp: BitDecomposed<Replicated<Gf2>>,
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
    pub async fn compute_row_with_previous<C, BK, TV, TS>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<BK, TV, TS>,
        num_saturating_sum_bits: usize,
        attribution_window_seconds: Option<NonZeroU32>,
    ) -> Result<CappedAttributionOutputs, Error>
    where
        C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
        BK: GaloisField,
        TV: GaloisField,
        TS: GaloisField,
    {
        let (bd_key, tv, timestamp) = (
            input_row.breakdown_key_bits(),
            input_row.trigger_value_bits(),
            input_row.timestamp_bits(),
        );

        assert_eq!(self.saturating_sum.sum.len(), num_saturating_sum_bits);

        let share_of_one = Replicated::share_known_value(&ctx, Gf2::ONE);
        let is_source_event = &share_of_one - &input_row.is_trigger_bit;

        let (
            ever_encountered_a_source_event,
            attributed_breakdown_key_bits,
            source_event_timestamp,
        ) = try_join3(
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
            timestamp_of_most_recent_source_event(
                ctx.narrow(&Step::SourceEventTimestamp),
                record_id,
                attribution_window_seconds,
                &input_row.is_trigger_bit,
                &self.source_event_timestamp,
                &timestamp,
            ),
        )
        .await?;

        let attributed_trigger_value = zero_out_trigger_value_unless_attributed(
            ctx.narrow(&Step::AttributedTriggerValue),
            record_id,
            &input_row.is_trigger_bit,
            &ever_encountered_a_source_event,
            &tv,
            attribution_window_seconds,
            &timestamp,
            &source_event_timestamp,
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
        self.source_event_timestamp = source_event_timestamp;

        let outputs_for_aggregation = CappedAttributionOutputs {
            attributed_breakdown_key_bits,
            capped_attributed_trigger_value,
        };
        Ok(outputs_for_aggregation)
    }
}

#[derive(Debug)]
pub struct CappedAttributionOutputs {
    pub attributed_breakdown_key_bits: BitDecomposed<Replicated<Gf2>>,
    pub capped_attributed_trigger_value: BitDecomposed<Replicated<Gf2>>,
}

impl ToBitConversionTriples for CappedAttributionOutputs {
    type Residual = ();

    fn bits(&self) -> u32 {
        (self.attributed_breakdown_key_bits.len() + self.capped_attributed_trigger_value.len())
            .try_into()
            .unwrap()
    }

    fn triple<F: PrimeField>(&self, role: Role, i: u32) -> BitConversionTriple<Replicated<F>> {
        assert!(i < self.bits());
        let i: usize = i.try_into().unwrap();
        let bit = if i < self.attributed_breakdown_key_bits.len() {
            &self.attributed_breakdown_key_bits[i]
        } else {
            let i = i - self.attributed_breakdown_key_bits.len();
            &self.capped_attributed_trigger_value[i]
        };
        BitConversionTriple::new(role, bit.left() == Gf2::ONE, bit.right() == Gf2::ONE)
    }

    fn into_triples<F, I>(
        self,
        role: Role,
        indices: I,
    ) -> (
        BitDecomposed<BitConversionTriple<Replicated<F>>>,
        Self::Residual,
    )
    where
        F: PrimeField,
        I: IntoIterator<Item = u32>,
    {
        (self.triple_range(role, indices), ())
    }
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
    PrimeFieldValidator,
    EverEncounteredSourceEvent,
    DidTriggerGetAttributed,
    AttributedBreakdownKey,
    AttributedTriggerValue,
    AttributedEventCheckFlag,
    CheckAttributionWindow,
    ComputeTimeDelta,
    CompareTimeDeltaToAttributionWindow,
    SourceEventTimestamp,
    ComputeSaturatingSum,
    IsSaturatedAndPrevRowNotSaturated,
    ComputeDifferenceToCap,
    ComputedCappedAttributedTriggerValueNotSaturatedCase,
    ComputedCappedAttributedTriggerValueJustSaturatedCase,
    ModulusConvertBreakdownKeyBitsAndTriggerValues,
    MoveValueToCorrectBreakdown,
}

pub trait GroupingKey {
    fn get_grouping_key(&self) -> u64;
}

pub fn compute_histogram_of_users_with_row_count<S>(input: &[S]) -> Vec<usize>
where
    S: GroupingKey,
{
    let mut histogram = vec![];
    let mut last_prf = input[0].get_grouping_key() + 1;
    let mut cur_count = 0;
    for row in input {
        if row.get_grouping_key() == last_prf {
            cur_count += 1;
        } else {
            cur_count = 0;
            last_prf = row.get_grouping_key();
        }
        if histogram.len() <= cur_count {
            histogram.push(0);
        }
        histogram[cur_count] += 1;
    }
    histogram
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

///
/// Takes an input stream of `PrfShardedIpaInputRecordRow` which is assumed to have all records with a given PRF adjacent
/// and converts it into a stream of vectors of `PrfShardedIpaInputRecordRow` having the same PRF.
///
/// Filters out any users that only have a single row, since they will produce no attributed conversions.
///
fn chunk_rows_by_user<IS, BK, TV, TS>(
    input_stream: IS,
    first_row: PrfShardedIpaInputRow<BK, TV, TS>,
) -> impl Stream<Item = Vec<PrfShardedIpaInputRow<BK, TV, TS>>>
where
    BK: GaloisField,
    TV: GaloisField,
    TS: GaloisField,
    IS: Stream<Item = PrfShardedIpaInputRow<BK, TV, TS>> + Unpin,
{
    unfold(Some((input_stream, first_row)), |state| async move {
        let (mut s, last_row) = state?;
        let mut last_row_prf = last_row.prf_of_match_key;
        let mut current_chunk = vec![last_row];
        while let Some(row) = s.next().await {
            if row.prf_of_match_key == last_row_prf {
                current_chunk.push(row);
            } else if current_chunk.len() > 1 {
                return Some((current_chunk, Some((s, row))));
            } else {
                last_row_prf = row.prf_of_match_key;
                current_chunk = vec![row];
            }
        }
        Some((current_chunk, None))
    })
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
pub async fn attribution_and_capping_and_aggregation<C, BK, TV, TS, S, F>(
    sh_ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<BK, TV, TS>>,
    num_saturating_sum_bits: usize,
    attribution_window_seconds: Option<NonZeroU32>,
    histogram: &[usize],
) -> Result<Vec<S>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable + SecureMul<C::UpgradedContext<F>>,
    BK: GaloisField,
    TV: GaloisField,
    TS: GaloisField,
    F: PrimeField + ExtendableField,
{
    assert!(num_saturating_sum_bits > TV::BITS as usize);
    assert!(TV::BITS > 0);
    assert!(BK::BITS > 0);
    assert!(TS::BITS > 0);

    // Get the validator and context to use for Gf2 multiplication operations
    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();

    // Get the validator and context to use for `Z_p` operations (modulus conversion)
    let prime_field_validator = sh_ctx.narrow(&Step::PrimeFieldValidator).validator::<F>();
    let prime_field_ctx = prime_field_validator.context();

    // Tricky hacks to work around the limitations of our current infrastructure
    let num_outputs = input_rows.len() - histogram[0];
    let mut record_id_for_row_depth = vec![0_u32; histogram.len()];
    let ctx_for_row_number = set_up_contexts(&binary_m_ctx, histogram);

    // Chunk the incoming stream of records into stream of vectors of records with the same PRF
    let mut input_stream = stream_iter(input_rows);
    let first_row = input_stream.next().await;
    if first_row.is_none() {
        return Ok(vec![]);
    }
    let first_row = first_row.unwrap();
    let rows_chunked_by_user = chunk_rows_by_user(input_stream, first_row);

    let mut collected = rows_chunked_by_user.collect::<Vec<_>>().await;
    collected.sort_by(|a, b| std::cmp::Ord::cmp(&b.len(), &a.len()));

    // Convert to a stream of async futures that represent the result of executing the per-user circuit
    let stream_of_per_user_circuits = pin!(stream_iter(collected).then(|rows_for_user| {
        let num_user_rows = rows_for_user.len();
        let contexts = ctx_for_row_number[..num_user_rows - 1].to_owned();
        let record_ids = record_id_for_row_depth[..num_user_rows].to_owned();

        for count in &mut record_id_for_row_depth[..num_user_rows] {
            *count += 1;
        }
        #[allow(clippy::async_yields_async)]
        // this is ok, because seq join wants a stream of futures
        async move {
            evaluate_per_user_attribution_circuit(
                contexts,
                record_ids,
                rows_for_user,
                num_saturating_sum_bits,
                attribution_window_seconds,
            )
        }
    }));

    // Execute all of the async futures (sequentially), and flatten the result
    let flattenned_stream = seq_join(sh_ctx.active_work(), stream_of_per_user_circuits)
        .flat_map(|x| stream_iter(x.unwrap()));

    // modulus convert breakdown keys and trigger values
    let converted_bks_and_tvs = convert_bits(
        prime_field_ctx
            .narrow(&Step::ModulusConvertBreakdownKeyBitsAndTriggerValues)
            .set_total_records(num_outputs),
        flattenned_stream,
        0..BK::BITS + TV::BITS,
    );

    // move each value to the correct bucket
    let row_contributions_stream = converted_bks_and_tvs
        .zip(futures::stream::repeat(
            prime_field_ctx
                .narrow(&Step::MoveValueToCorrectBreakdown)
                .set_total_records(num_outputs),
        ))
        .enumerate()
        .map(|(i, (bk_and_tv_bits, ctx))| {
            let record_id: RecordId = RecordId::from(i);
            let bk_and_tv_bits = bk_and_tv_bits.unwrap();
            let (bk_bits, tv_bits) = bk_and_tv_bits.split_at(BK::BITS);
            async move {
                bucket::move_single_value_to_bucket::<BK, _, _, _>(
                    ctx,
                    record_id,
                    bk_bits,
                    BitDecomposed::to_additive_sharing_in_large_field_consuming(tv_bits),
                    1 << BK::BITS,
                    false,
                )
                .await
            }
        });

    // aggregate all row level contributions
    let row_contributions = seq_join(prime_field_ctx.active_work(), row_contributions_stream);
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

async fn evaluate_per_user_attribution_circuit<C, BK, TV, TS>(
    ctx_for_row_number: Vec<C>,
    record_id_for_each_depth: Vec<u32>,
    rows_for_user: Vec<PrfShardedIpaInputRow<BK, TV, TS>>,
    num_saturating_sum_bits: usize,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<CappedAttributionOutputs>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    BK: GaloisField,
    TV: GaloisField,
    TS: GaloisField,
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
        let record_id_for_this_row_depth = RecordId::from(record_id_for_each_depth[i + 1]); // skip row 0

        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(
                ctx_for_this_row_depth,
                record_id_for_this_row_depth,
                row,
                num_saturating_sum_bits,
                attribution_window_seconds,
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
fn initialize_new_device_attribution_variables<BK, TV, TS>(
    share_of_one: Replicated<Gf2>,
    input_row: &PrfShardedIpaInputRow<BK, TV, TS>,
    num_saturating_sum_bits: usize,
) -> InputsRequiredFromPrevRow
where
    BK: GaloisField,
    TV: GaloisField,
    TS: GaloisField,
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
        source_event_timestamp: BitDecomposed::decompose(TS::BITS, |i| {
            input_row.timestamp.map(|v| Gf2::truncate_from(v[i]))
        }),
    }
}

///
/// To support "Last Touch Attribution" we move the `breakdown_key` of the most recent source event
/// down to all of trigger events that follow it.
///
/// The logic here is extremely simple. For each row:
/// (a) if it is a source event, take the current `breakdown_key`.
/// (b) if it is a trigger event, take the `breakdown_key` from the preceding line
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

/// Same as above but for timestamps. If `attribution_window_seconds` is `None`, just
/// return the previous row's timestamp. The bits aren't used but saves some multiplications.
async fn timestamp_of_most_recent_source_event<C>(
    ctx: C,
    record_id: RecordId,
    attribution_window_seconds: Option<NonZeroU32>,
    is_trigger_bit: &Replicated<Gf2>,
    prev_row_timestamp_bits: &BitDecomposed<Replicated<Gf2>>,
    cur_row_timestamp_bits: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    match attribution_window_seconds {
        None => Ok(prev_row_timestamp_bits.clone()),
        Some(_) => {
            Ok(BitDecomposed::new(
                ctx
                    .parallel_join(
                        cur_row_timestamp_bits
                            .iter()
                            .zip(prev_row_timestamp_bits.iter())
                            .enumerate()
                            .map(|(i, (cur_bit, prev_bit))| {
                                let c = ctx.narrow(&BitOpStep::from(i));
                                async move {
                                    if_else(c, record_id, is_trigger_bit, prev_bit, cur_bit).await
                                }
                            }),
                    )
                    .await?,
            ))
        }
    }
}

///
/// In this simple "Last Touch Attribution" model, the `trigger_value` of a trigger event is either
/// (a) Attributed to a single `breakdown_key`
/// (b) Not attributed, and thus zeroed out
///
/// The logic here is extremely simple. There is a secret-shared bit indicating if a given row is an "attributed trigger event" and
/// another secret-shared bit indicating if a given row is within the attribution window. We multiply these two bits together and
/// multiply it with the bits of the `trigger_value` in order to zero out contributions from unattributed trigger events.
///
#[allow(clippy::too_many_arguments)]
async fn zero_out_trigger_value_unless_attributed<C>(
    ctx: C,
    record_id: RecordId,
    is_trigger_bit: &Replicated<Gf2>,
    ever_encountered_a_source_event: &Replicated<Gf2>,
    trigger_value: &BitDecomposed<Replicated<Gf2>>,
    attribution_window_seconds: Option<NonZeroU32>,
    trigger_event_timestamp: &BitDecomposed<Replicated<Gf2>>,
    source_event_timestamp: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    let (did_trigger_get_attributed, is_trigger_within_window) = try_join(
        is_trigger_bit.multiply(
            ever_encountered_a_source_event,
            ctx.narrow(&Step::DidTriggerGetAttributed),
            record_id,
        ),
        is_trigger_event_within_attribution_window(
            ctx.narrow(&Step::CheckAttributionWindow),
            record_id,
            attribution_window_seconds,
            trigger_event_timestamp,
            source_event_timestamp,
        ),
    )
    .await?;

    // save 1 multiplication if there is no attribution window
    let zero_out_flag = if attribution_window_seconds.is_some() {
        let c = ctx.narrow(&Step::AttributedEventCheckFlag);
        did_trigger_get_attributed
            .multiply(&is_trigger_within_window, c, record_id)
            .await?
    } else {
        did_trigger_get_attributed.clone()
    };

    Ok(BitDecomposed::new(
        ctx.parallel_join(
            trigger_value
                .iter()
                .zip(repeat(zero_out_flag))
                .enumerate()
                .map(|(i, (trigger_value_bit, zero_out_flag))| {
                    let c = ctx.narrow(&BitOpStep::from(i));
                    async move {
                        trigger_value_bit
                            .multiply(&zero_out_flag, c, record_id)
                            .await
                    }
                }),
        )
        .await?,
    ))
}

/// If the `attribution_window_seconds` is not `None`, we calculate the time
/// difference between the trigger event and the most recent source event, and
/// returns a secret-shared bit indicating if the trigger event is within the
/// attribution window.
async fn is_trigger_event_within_attribution_window<C>(
    ctx: C,
    record_id: RecordId,
    attribution_window_seconds: Option<NonZeroU32>,
    trigger_event_timestamp: &BitDecomposed<Replicated<Gf2>>,
    source_event_timestamp: &BitDecomposed<Replicated<Gf2>>,
) -> Result<Replicated<Gf2>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    if let Some(attribution_window_seconds) = attribution_window_seconds {
        assert_eq!(trigger_event_timestamp.len(), source_event_timestamp.len());

        let time_delta_bits = trigger_event_timestamp
            .sub(
                ctx.narrow(&Step::ComputeTimeDelta),
                record_id,
                source_event_timestamp,
            )
            .await?;

        // The result is true if the time delta is `[0, attribution_window_seconds)`
        // If we want to include the upper bound, we need to use `bitwise_greater_than_constant()`
        // and negate the result.
        // TODO: Change to `lte` protocol once #844 is landed.
        bitwise_less_than_constant(
            ctx.narrow(&Step::CompareTimeDeltaToAttributionWindow),
            record_id,
            &time_delta_bits,
            u128::from(attribution_window_seconds.get()),
        )
        .await
    } else {
        // if there is no attribution window, then all trigger events are attributed
        Ok(Replicated::share_known_value(&ctx, Gf2::ONE))
    }
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

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::num::NonZeroU32;

    use super::{CappedAttributionOutputs, PrfShardedIpaInputRow};
    use crate::{
        ff::{Field, Fp32BitPrime, GaloisField, Gf2, Gf20Bit, Gf3Bit, Gf5Bit},
        protocol::ipa_prf::prf_sharding::attribution_and_capping_and_aggregation,
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, IntoShares,
            SharedValue,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<BK: GaloisField, TV: GaloisField, TS: GaloisField> {
        prf_of_match_key: u64,
        is_trigger_bit: Gf2,
        breakdown_key: BK,
        trigger_value: TV,
        timestamp: TS,
    }

    fn oprf_test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        breakdown_key: u8,
        trigger_value: u8,
    ) -> PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit, Gf20Bit> {
        oprf_test_input_with_timestamp(
            prf_of_match_key,
            is_trigger,
            breakdown_key,
            trigger_value,
            0,
        )
    }

    fn oprf_test_input_with_timestamp(
        prf_of_match_key: u64,
        is_trigger: bool,
        breakdown_key: u8,
        trigger_value: u8,
        timestamp: u32,
    ) -> PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit, Gf20Bit> {
        let is_trigger_bit = if is_trigger { Gf2::ONE } else { Gf2::ZERO };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            breakdown_key: Gf5Bit::truncate_from(breakdown_key),
            trigger_value: Gf3Bit::truncate_from(trigger_value),
            timestamp: Gf20Bit::truncate_from(timestamp),
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

    impl<BK, TV, TS> IntoShares<PrfShardedIpaInputRow<BK, TV, TS>>
        for PreShardedAndSortedOPRFTestInput<BK, TV, TS>
    where
        BK: GaloisField + IntoShares<Replicated<BK>>,
        TV: GaloisField + IntoShares<Replicated<TV>>,
        TS: GaloisField + IntoShares<Replicated<TS>>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [PrfShardedIpaInputRow<BK, TV, TS>; 3] {
            let PreShardedAndSortedOPRFTestInput {
                prf_of_match_key,
                is_trigger_bit,
                breakdown_key,
                trigger_value,
                timestamp,
            } = self;

            let [is_trigger_bit0, is_trigger_bit1, is_trigger_bit2] =
                is_trigger_bit.share_with(rng);
            let [breakdown_key0, breakdown_key1, breakdown_key2] = breakdown_key.share_with(rng);
            let [trigger_value0, trigger_value1, trigger_value2] = trigger_value.share_with(rng);
            let [timestamp0, timestamp1, timestamp2] = timestamp.share_with(rng);

            [
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit0,
                    breakdown_key: breakdown_key0,
                    trigger_value: trigger_value0,
                    timestamp: timestamp0,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit1,
                    breakdown_key: breakdown_key1,
                    trigger_value: trigger_value1,
                    timestamp: timestamp1,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit2,
                    breakdown_key: breakdown_key2,
                    trigger_value: trigger_value2,
                    timestamp: timestamp2,
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

            let [attributed_breakdown_key0, attributed_breakdown_key1, attributed_breakdown_key2] =
                attributed_breakdown_key.share_with(rng);
            let [capped_attributed_trigger_value0, capped_attributed_trigger_value1, capped_attributed_trigger_value2] =
                capped_attributed_trigger_value.share_with(rng);

            [
                CappedAttributionOutputs {
                    attributed_breakdown_key_bits: attributed_breakdown_key0,
                    capped_attributed_trigger_value: capped_attributed_trigger_value0,
                },
                CappedAttributionOutputs {
                    attributed_breakdown_key_bits: attributed_breakdown_key1,
                    capped_attributed_trigger_value: capped_attributed_trigger_value1,
                },
                CappedAttributionOutputs {
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
    fn semi_honest_aggregation_capping_attribution() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit, Gf20Bit>> = vec![
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

            let histogram = [3, 3, 2, 2, 1, 1, 1, 1];

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    attribution_and_capping_and_aggregation::<
                        _,
                        Gf5Bit,
                        Gf3Bit,
                        Gf20Bit,
                        Replicated<Fp32BitPrime>,
                        Fp32BitPrime,
                    >(ctx, input_rows, num_saturating_bits, None, &histogram)
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }

    #[test]
    fn semi_honest_aggregation_capping_attribution_with_attribution_window() {
        // In OPRF, the attribution window's upper bound is excluded - i.e., [0..ATTRIBUTION_WINDOW_SECONDS).
        // Ex. If attribution window is 200s and the time difference from the nearest source event
        // to the trigger event is 200s, then the trigger event is NOT attributed.
        // TODO: Modify the test case once #844 is landed. i.e., change the second test input row ts to `201`.
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 200;

        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf5Bit, Gf3Bit, Gf20Bit>> = vec![
                /* First User */
                oprf_test_input_with_timestamp(123, false, 17, 0, 1),
                oprf_test_input_with_timestamp(123, true, 0, 7, 200), // tsΔ = 199, attributed to 17
                oprf_test_input_with_timestamp(123, false, 20, 0, 200),
                oprf_test_input_with_timestamp(123, true, 0, 3, 300), // tsΔ = 100, attributed to 20
                /* Second User */
                oprf_test_input_with_timestamp(234, false, 12, 0, 0),
                oprf_test_input_with_timestamp(234, true, 0, 5, 199), // tsΔ = 199, attributed to 12
                /* Third User */
                oprf_test_input_with_timestamp(345, false, 20, 0, 0),
                oprf_test_input_with_timestamp(345, true, 0, 3, 100), // tsΔ = 100, attributed to 20
                oprf_test_input_with_timestamp(345, false, 18, 0, 200),
                oprf_test_input_with_timestamp(345, false, 12, 0, 300),
                oprf_test_input_with_timestamp(345, true, 0, 3, 400), // tsΔ = 100, attributed to 12
                oprf_test_input_with_timestamp(345, true, 0, 3, 499), // tsΔ = 199, attributed to 12
                oprf_test_input_with_timestamp(345, true, 0, 3, 500), // tsΔ = 200, not attributed
                oprf_test_input_with_timestamp(345, true, 0, 3, 700), // tsΔ = 400, not attributed
            ];

            let mut expected = [0_u128; 32];
            expected[12] = 11;
            expected[17] = 7;
            expected[20] = 6;

            let num_saturating_bits: usize = 5;

            let histogram = [3, 3, 2, 2, 1, 1, 1, 1];

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    attribution_and_capping_and_aggregation::<
                        _,
                        Gf5Bit,
                        Gf3Bit,
                        Gf20Bit,
                        Replicated<Fp32BitPrime>,
                        Fp32BitPrime,
                    >(
                        ctx,
                        input_rows,
                        num_saturating_bits,
                        NonZeroU32::new(ATTRIBUTION_WINDOW_SECONDS),
                        &histogram,
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
