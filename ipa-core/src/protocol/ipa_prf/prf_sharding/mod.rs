use std::{
    convert::Infallible,
    iter,
    iter::zip,
    num::NonZeroU32,
    ops::{Not, Range},
};

use futures::{
    future::{try_join, try_join3},
    stream::{self, unfold},
    FutureExt, Stream, StreamExt, TryStreamExt,
};

use super::aggregation::{aggregate_contributions, breakdown_reveal::breakdown_reveal_aggregation};
use crate::{
    error::{Error, LengthError},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA32, BA7},
        ArrayAccess, Field, U128Conversions,
    },
    helpers::{repeat_n, stream::TryFlattenItersExt, TotalRecords},
    protocol::{
        basics::{select, BooleanArrayMul, BooleanProtocols, SecureMul, ShareKnownValue},
        boolean::{
            or::or,
            step::{EightBitStep, ThirtyTwoBitStep},
            NBitStep,
        },
        context::{
            dzkp_validator::{DZKPValidator, TARGET_PROOF_SIZE},
            Context, DZKPContext, DZKPUpgraded, UpgradableContext,
        },
        ipa_prf::{
            boolean_ops::{
                addition_sequential::integer_add,
                comparison_and_subtraction_sequential::{compare_gt, integer_sub},
                expand_shared_array_in_place,
            },
            prf_sharding::step::{
                AttributionPerRowStep as PerRowStep, AttributionStep as Step,
                AttributionWindowStep as WindowStep,
                AttributionZeroOutTriggerStep as ZeroOutTriggerStep, UserNthRowStep,
            },
            BreakdownKey, AGG_CHUNK,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, SharedValue, TransposeFrom,
    },
};

pub mod feature_label_dot_product;
pub(crate) mod step;

#[derive(Debug)]
pub struct PrfShardedIpaInputRow<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
    pub prf_of_match_key: u64,
    pub is_trigger_bit: Replicated<Boolean>,
    pub breakdown_key: Replicated<BK>,
    pub trigger_value: Replicated<TV>,
    pub timestamp: Replicated<TS>,
    pub sort_key: Replicated<BA32>,
}

impl<BK: SharedValue, TS, TV: SharedValue> PrfShardedIpaInputRow<BK, TV, TS>
where
    TS: BooleanArray,
{
    /// This function defines the sort key.
    /// The order of sorting is `timestamp`, `is_trigger_bit`, `counter`.
    /// We sort by `is_trigger_bit` to ensure source events come before trigger in case there
    /// is a tie in timestamp
    /// Counter is added to ensure each sorting key is unique to avoid privacy leakage
    /// NOTE: the sort key will be interpreted in Little endian format, so the order in
    /// which things are appended is important.
    /// We still need to add epoch which will be added later
    pub fn compute_sort_key(&mut self, counter: u64) {
        expand_shared_array_in_place(
            &mut self.sort_key,
            &Replicated::new(BA7::truncate_from(counter), BA7::truncate_from(counter)),
            0,
        );
        let mut offset = BA7::BITS as usize;

        self.sort_key.set(offset, self.is_trigger_bit.clone());

        offset += 1;
        expand_shared_array_in_place(&mut self.sort_key, &self.timestamp, offset);
        // TODO(richaj): add epoch to sort key computation
    }
}

impl<BK: SharedValue, TS: SharedValue, TV: SharedValue> GroupingKey
    for PrfShardedIpaInputRow<BK, TV, TS>
{
    fn get_grouping_key(&self) -> u64 {
        self.prf_of_match_key
    }
}

struct InputsRequiredFromPrevRow<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
    ever_encountered_a_source_event: Replicated<Boolean>,
    attributed_breakdown_key_bits: Replicated<BK>,
    saturating_sum: BitDecomposed<Replicated<Boolean>>,
    is_saturated: Replicated<Boolean>,
    difference_to_cap: Replicated<TV>,
    source_event_timestamp: Replicated<TS>,
}

/// Returns the number of Boolean multiplications per input record, for use in computing the number
/// of records in each DZKP. These multiplications are in `compute_row_with_previous` and the
/// functions it calls.
fn multiplications_per_record<BK: SharedValue, TV: SharedValue, TS: SharedValue>(
    attribution_window: Option<NonZeroU32>,
) -> usize {
    let mut count =
        // breakdown_key_of_most_recent_source_event
        BK::BITS +
        // zero_out_trigger_value_unless_attributed
        // cumulative trigger value sum
        // difference to cap
        // compute_capped_trigger_value (2x)
        5 * TV::BITS +
        // ever_encountered_a_source_event
        // overflow_bit_and_prev_row_not_saturated
        // did_trigger_get_attributed
        3;

    if attribution_window.is_some() {
        count +=
            // timestamp_of_most_recent_source_event
            // time_delta_bits
            // time_delta_gt_attribution_window
            3 * TS::BITS +
            // zero_out_flag
            1;
    }

    usize::try_from(count).unwrap()
}

impl<BK, TV, TS> InputsRequiredFromPrevRow<BK, TV, TS>
where
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
{
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
    pub async fn compute_row_with_previous<C>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<BK, TV, TS>,
        attribution_window_seconds: Option<NonZeroU32>,
    ) -> Result<AttributionOutputs<Replicated<BK>, Replicated<TV>>, Error>
    where
        C: Context,
        Replicated<Boolean>: BooleanProtocols<C>,
        Replicated<BK>: BooleanArrayMul<C>,
        Replicated<TS>: BooleanArrayMul<C>,
        Replicated<TV>: BooleanArrayMul<C>,
    {
        let is_source_event = input_row.is_trigger_bit.clone().not();

        let (
            ever_encountered_a_source_event,
            attributed_breakdown_key_bits,
            source_event_timestamp,
        ) = try_join3(
            or(
                ctx.narrow(&PerRowStep::EverEncounteredSourceEvent),
                record_id,
                &is_source_event,
                &self.ever_encountered_a_source_event,
            ),
            breakdown_key_of_most_recent_source_event(
                ctx.narrow(&PerRowStep::AttributedBreakdownKey),
                record_id,
                &input_row.is_trigger_bit,
                &self.attributed_breakdown_key_bits,
                &input_row.breakdown_key,
            ),
            timestamp_of_most_recent_source_event(
                ctx.narrow(&PerRowStep::SourceEventTimestamp),
                record_id,
                attribution_window_seconds,
                &input_row.is_trigger_bit,
                &self.source_event_timestamp,
                &input_row.timestamp,
            ),
        )
        .await?;

        let attributed_trigger_value = zero_out_trigger_value_unless_attributed(
            ctx.narrow(&PerRowStep::AttributedTriggerValue),
            record_id,
            &input_row.is_trigger_bit,
            &ever_encountered_a_source_event,
            &input_row.trigger_value,
            attribution_window_seconds,
            &input_row.timestamp,
            &source_event_timestamp,
        )
        .await?;

        assert!(
            TV::BITS <= EightBitStep::BITS,
            "EightBitStep not large enough to accomodate this sum"
        );
        let (updated_sum, overflow_bit) = integer_add::<_, EightBitStep, 1>(
            ctx.narrow(&PerRowStep::ComputeSaturatingSum),
            record_id,
            &self.saturating_sum,
            &attributed_trigger_value.to_bits(),
        )
        .await?;

        assert!(
            TV::BITS <= EightBitStep::BITS,
            "EightBitStep not large enough to accomodate this subtraction"
        );
        let (overflow_bit_and_prev_row_not_saturated, difference_to_cap) = try_join(
            overflow_bit.multiply(
                &self.is_saturated.clone().not(),
                ctx.narrow(&PerRowStep::IsSaturatedAndPrevRowNotSaturated),
                record_id,
            ),
            // It is okay that we are calling `integer_sub` with length(y) > length(x) here.
            // `difference_to_cap` only needs to be accurate in the case where the next row will
            // overflow. When that is the case, `updated_sum` must be within `2^TV::BITS` of the
            // cap, and a `TV::BITS` subtraction of the `TV::BITS` least significant bits of
            // `updated_sum` from zero will correctly compute the difference to the cap.
            integer_sub::<_, EightBitStep>(
                ctx.narrow(&PerRowStep::ComputeDifferenceToCap),
                record_id,
                &BitDecomposed::new(repeat_n(
                    Replicated::ZERO,
                    usize::try_from(TV::BITS).unwrap(),
                )),
                &updated_sum,
            )
            .map(|res| res.map(BitDecomposed::collect_bits)),
        )
        .await?;

        // Tricky way of expressing an `OR` condition, but with no additional multiplications:
        //   Logically: "Did this row just become saturated OR was the previous row already saturated"
        //   This works because these conditions cannot both be true
        let is_saturated = &self.is_saturated + &overflow_bit_and_prev_row_not_saturated;

        let capped_attributed_trigger_value = compute_capped_trigger_value(
            ctx,
            record_id,
            &is_saturated,
            &overflow_bit_and_prev_row_not_saturated,
            &self.difference_to_cap,
            &attributed_trigger_value,
        )
        .await?;

        self.ever_encountered_a_source_event = ever_encountered_a_source_event;
        self.attributed_breakdown_key_bits = attributed_breakdown_key_bits.clone();
        self.saturating_sum = updated_sum;
        self.is_saturated = is_saturated;
        self.difference_to_cap = difference_to_cap;
        self.source_event_timestamp = source_event_timestamp;

        let outputs_for_aggregation = AttributionOutputs {
            attributed_breakdown_key_bits,
            capped_attributed_trigger_value,
        };
        Ok(outputs_for_aggregation)
    }
}

/// Container for a record output from the attribution stage.
///
/// Attribution output consists of a series of pairs of an attributed trigger value and the
/// breakdown to which that trigger value should be credited.
///
/// The `aggregation` module also uses this type to hold chunks of attribution output records by
/// specifying vectorized types for `BK` and `TV`.
///
///

#[derive(Clone, Debug, Default)]
pub struct AttributionOutputs<BK, TV> {
    pub attributed_breakdown_key_bits: BK,
    pub capped_attributed_trigger_value: TV,
}

pub type SecretSharedAttributionOutputs<BK, TV> =
    AttributionOutputs<Replicated<BK>, Replicated<TV>>;

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
#[derive(Debug, Clone, Ord, PartialEq, PartialOrd, Eq)]
pub struct AttributionOutputsTestInput<BK: BooleanArray, TV: BooleanArray> {
    pub bk: BK,
    pub tv: TV,
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
impl<BK, TV> crate::secret_sharing::IntoShares<(Replicated<BK>, Replicated<TV>)>
    for AttributionOutputsTestInput<BK, TV>
where
    BK: BooleanArray + crate::secret_sharing::IntoShares<Replicated<BK>>,
    TV: BooleanArray + crate::secret_sharing::IntoShares<Replicated<TV>>,
{
    fn share_with<R: rand::Rng>(self, rng: &mut R) -> [(Replicated<BK>, Replicated<TV>); 3] {
        let [bk_0, bk_1, bk_2] = self.bk.share_with(rng);
        let [tv_0, tv_1, tv_2] = self.tv.share_with(rng);
        [(bk_0, tv_0), (bk_1, tv_1), (bk_2, tv_2)]
    }
}

pub trait GroupingKey {
    fn get_grouping_key(&self) -> u64;
}

#[tracing::instrument(name = "histograms_ranges_sortkeys", skip_all)]
/// This function does following computations per user
/// 1. Compute histogram of users with row counts. `histogram[row number]` contains the count of
///    users having that row number (i.e. the count of users with at least row_number+1 records)
/// 2. Compute range of rows for each user in the input vector
/// 3. Compute the sort key for the input rows which is used later for sorting
pub fn histograms_ranges_sortkeys<BK, TV, TS>(
    input: &mut [PrfShardedIpaInputRow<BK, TV, TS>],
) -> (Vec<usize>, Vec<Range<usize>>)
where
    BK: BooleanArray,
    TV: BooleanArray,
    TS: BooleanArray,
{
    let mut histogram = vec![];
    let mut last_prf = 0;
    let mut cur_count = 0;
    let mut start = 0;
    let mut ranges = vec![];
    for (idx, row) in input.iter_mut().enumerate() {
        if idx != 0 && row.get_grouping_key() == last_prf {
            cur_count += 1;
        } else {
            if idx > 0 {
                ranges.push(start..idx);
            }
            start = idx;
            cur_count = 0;
            last_prf = row.get_grouping_key();
        }

        row.compute_sort_key(cur_count.try_into().unwrap());
        if histogram.len() <= cur_count {
            histogram.push(0);
        }
        histogram[cur_count] += 1;
    }
    ranges.push(start..input.len());
    (histogram, ranges)
}

fn set_up_contexts<C>(
    root_ctx: C,
    chunk_size: usize,
    histogram: &[usize],
) -> Result<(C::DZKPValidator, Vec<DZKPUpgraded<C>>), Error>
where
    C: UpgradableContext,
{
    let mut dzkp_validator = root_ctx.dzkp_validator(chunk_size);
    let ctx = dzkp_validator.context();
    dzkp_validator.set_total_records(TotalRecords::specified(histogram[1]).unwrap());

    let mut context_per_row_depth = Vec::with_capacity(histogram.len());
    for (row_number, num_users_having_that_row_number) in histogram.iter().enumerate() {
        if row_number == 0 {
            // no multiplications needed for each user's row 0. No context needed
        } else {
            let total_records = TotalRecords::specified(*num_users_having_that_row_number)?;
            let ctx_for_row_number = ctx
                .narrow(&UserNthRowStep::from(row_number))
                .set_total_records(total_records);
            context_per_row_depth.push(ctx_for_row_number);
        }
    }
    Ok((dzkp_validator, context_per_row_depth))
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
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
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
        (current_chunk.len() > 1).then_some((current_chunk, None))
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
/// This circuit will compute attribution, per-user capping and aggregation.
///
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
#[tracing::instrument(name = "attribute_cap_aggregate", skip_all)]
pub async fn attribute_cap_aggregate<
    'ctx,
    C,
    BK,
    TV,
    HV,
    TS,
    const SS_BITS: usize,
    const B: usize,
>(
    sh_ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
    histogram: &[usize],
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: UpgradableContext + 'ctx,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Boolean: FieldSimd<B>,
    Replicated<Boolean>: BooleanProtocols<DZKPUpgraded<C>>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    Replicated<Boolean, AGG_CHUNK>: BooleanProtocols<DZKPUpgraded<C>, AGG_CHUNK>,
    Replicated<BK>: BooleanArrayMul<DZKPUpgraded<C>>,
    Replicated<TS>: BooleanArrayMul<DZKPUpgraded<C>>,
    Replicated<TV>: BooleanArrayMul<DZKPUpgraded<C>>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, AGG_CHUNK>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<TV>>, Error = LengthError>,
    Vec<BitDecomposed<Replicated<Boolean, B>>>: for<'a> TransposeFrom<
        &'a [BitDecomposed<Replicated<Boolean, AGG_CHUNK>>],
        Error = Infallible,
    >,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    // Get the validator and context to use for Boolean multiplication operations.
    // Record IDs count users. The maximum number of multiplications per record (user) is:
    // (max_events - 1) * multiplictions_per_record, because the attribution circuit is
    // only evaluated for the second and subsequent records.
    let chunk_size = TARGET_PROOF_SIZE
        / ((histogram.len() - 1)
            * multiplications_per_record::<BK, TV, TS>(attribution_window_seconds));

    // Tricky hacks to work around the limitations of our current infrastructure
    let num_outputs = input_rows.len() - histogram[0];
    let (dzkp_validator, ctx_for_row_number) =
        set_up_contexts(sh_ctx.narrow(&Step::Attribute), chunk_size, histogram)?;

    // Chunk the incoming stream of records into stream of vectors of records with the same PRF
    let mut input_stream = stream::iter(input_rows);
    let Some(first_row) = input_stream.next().await else {
        return Ok(BitDecomposed::new(
            iter::repeat(Replicated::<Boolean, B>::ZERO).take(B),
        ));
    };
    let rows_chunked_by_user = chunk_rows_by_user(input_stream, first_row);

    let mut collected = rows_chunked_by_user.collect::<Vec<_>>().await;
    collected.sort_by(|a, b| std::cmp::Ord::cmp(&b.len(), &a.len()));

    let flattened_user_results = attribute::<_, _, _, _, SS_BITS, B>(
        dzkp_validator,
        ctx_for_row_number,
        collected,
        attribution_window_seconds,
    );

    let aggregation_validator = sh_ctx.narrow(&Step::Aggregate).dzkp_validator(0);
    let ctx = aggregation_validator.context();

    // New aggregation is still experimental, we need proofs that it is private,
    // hence it is only enabled behind a feature flag.
    if cfg!(feature = "reveal-aggregation") {
        // If there was any error in attribution we stop the execution with an error
        tracing::warn!("Using the experimental aggregation based on revealing breakdown keys");
        let user_contributions = flattened_user_results.try_collect::<Vec<_>>().await?;
        breakdown_reveal_aggregation::<_, _, _, HV, B>(ctx, user_contributions).await
    } else {
        aggregate_contributions::<_, _, _, _, HV, B>(
            sh_ctx.narrow(&Step::Aggregate),
            flattened_user_results,
            num_outputs,
        )
        .await
    }
}

#[tracing::instrument(name = "attribute_cap", skip_all, fields(unique_match_keys = input.len()))]
fn attribute<'ctx, V, BK, TV, TS, const SS_BITS: usize, const B: usize>(
    dzkp_validator: V,
    contexts: Vec<V::Context>,
    input: Vec<Vec<PrfShardedIpaInputRow<BK, TV, TS>>>,
    attribution_window_seconds: Option<NonZeroU32>,
) -> impl Stream<Item = Result<SecretSharedAttributionOutputs<BK, TV>, Error>> + Send + 'ctx
where
    V: DZKPValidator + 'ctx,
    Replicated<Boolean>: BooleanProtocols<V::Context>,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Replicated<BK>: BooleanArrayMul<V::Context>,
    Replicated<TS>: BooleanArrayMul<V::Context>,
    Replicated<TV>: BooleanArrayMul<V::Context>,
{
    let chunked_user_results =
        input
            .into_iter()
            .enumerate()
            .map(move |(record_id, rows_for_user)| {
                let num_user_rows = rows_for_user.len();
                let contexts = contexts[..num_user_rows - 1].to_owned();

                evaluate_per_user_attribution_circuit::<_, BK, TV, TS, SS_BITS>(
                    contexts,
                    RecordId::from(record_id),
                    rows_for_user,
                    attribution_window_seconds,
                )
            });

    dzkp_validator
        .validated_seq_join::<_, _, Vec<AttributionOutputs<_, _>>>(stream::iter(
            chunked_user_results,
        ))
        .try_flatten_iters()
}

#[tracing::instrument(level = "debug", name = "per_user", skip_all, fields(rows = rows_for_user.len()))]
async fn evaluate_per_user_attribution_circuit<C, BK, TV, TS, const SS_BITS: usize>(
    ctx_for_row_number: Vec<C>,
    record_id: RecordId,
    rows_for_user: Vec<PrfShardedIpaInputRow<BK, TV, TS>>,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<SecretSharedAttributionOutputs<BK, TV>>, Error>
where
    C: DZKPContext,
    Replicated<Boolean>: BooleanProtocols<C>,
    BK: BooleanArray + U128Conversions,
    TV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Replicated<BK>: BooleanArrayMul<C>,
    Replicated<TS>: BooleanArrayMul<C>,
    Replicated<TV>: BooleanArrayMul<C>,
{
    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(Vec::new());
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs =
        initialize_new_device_attribution_variables::<BK, TV, TS, SS_BITS>(first_row);

    let mut output = Vec::with_capacity(rows_for_user.len() - 1);
    for (row, ctx) in zip(rows_for_user.iter().skip(1), ctx_for_row_number.into_iter()) {
        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(ctx, record_id, row, attribution_window_seconds)
            .await?;

        output.push(capped_attribution_outputs);
    }
    Ok(output)
}

///
/// Upon encountering the first row of data from a new user (as distinguished by a different OPRF of the match key)
/// this function encapsulates the variables that must be initialized. No communication is required for this first row.
///
fn initialize_new_device_attribution_variables<BK, TV, TS, const SS_BITS: usize>(
    input_row: &PrfShardedIpaInputRow<BK, TV, TS>,
) -> InputsRequiredFromPrevRow<BK, TV, TS>
where
    BK: SharedValue,
    TV: SharedValue,
    TS: SharedValue,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_source_event: input_row.is_trigger_bit.clone().not(),
        attributed_breakdown_key_bits: input_row.breakdown_key.clone(),
        saturating_sum: BitDecomposed::new(repeat_n(Replicated::ZERO, SS_BITS)),
        is_saturated: Replicated::<Boolean>::ZERO,
        // This is incorrect in the case that the CAP is less than the maximum value of "trigger value" for a single row
        // Not a problem if you assume that's an invalid input
        difference_to_cap: Replicated::<TV>::ZERO,
        source_event_timestamp: input_row.timestamp.clone(),
    }
}

///
/// To support "Last Touch Attribution" we move the `breakdown_key` of the most recent source event
/// down to all of trigger events that follow it.
///
/// The logic here is extremely simple. For each row:
/// (a) if it is a source event, take the current `breakdown_key`.
/// (b) if it is a trigger event, take the `breakdown_key` from the preceding line
async fn breakdown_key_of_most_recent_source_event<C, BK>(
    ctx: C,
    record_id: RecordId,
    is_trigger_bit: &Replicated<Boolean>,
    prev_row_breakdown_key_bits: &Replicated<BK>,
    cur_row_breakdown_key_bits: &Replicated<BK>,
) -> Result<Replicated<BK>, Error>
where
    C: Context,
    BK: BooleanArray,
    Replicated<BK>: BooleanArrayMul<C>,
{
    select(
        ctx,
        record_id,
        is_trigger_bit,
        prev_row_breakdown_key_bits,
        cur_row_breakdown_key_bits,
    )
    .await
}

/// Same as above but for timestamps. If `attribution_window_seconds` is `None`, just
/// return the previous row's timestamp. The bits aren't used but saves some multiplications.
async fn timestamp_of_most_recent_source_event<C, TS>(
    ctx: C,
    record_id: RecordId,
    attribution_window_seconds: Option<NonZeroU32>,
    is_trigger_bit: &Replicated<Boolean>,
    prev_row_timestamp_bits: &Replicated<TS>,
    cur_row_timestamp_bits: &Replicated<TS>,
) -> Result<Replicated<TS>, Error>
where
    C: Context,
    TS: BooleanArray + U128Conversions,
    Replicated<TS>: BooleanArrayMul<C>,
{
    match attribution_window_seconds {
        None => Ok(prev_row_timestamp_bits.clone()),
        Some(_) => {
            select(
                ctx,
                record_id,
                is_trigger_bit,
                prev_row_timestamp_bits,
                cur_row_timestamp_bits,
            )
            .await
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
async fn zero_out_trigger_value_unless_attributed<C, TV, TS>(
    ctx: C,
    record_id: RecordId,
    is_trigger_bit: &Replicated<Boolean>,
    ever_encountered_a_source_event: &Replicated<Boolean>,
    trigger_value: &Replicated<TV>,
    attribution_window_seconds: Option<NonZeroU32>,
    trigger_event_timestamp: &Replicated<TS>,
    source_event_timestamp: &Replicated<TS>,
) -> Result<Replicated<TV>, Error>
where
    C: Context,
    TV: BooleanArray + U128Conversions,
    TS: BooleanArray + U128Conversions,
    Replicated<Boolean>: BooleanProtocols<C>,
    Replicated<TV>: BooleanArrayMul<C>,
{
    let (did_trigger_get_attributed, is_trigger_within_window) = try_join(
        is_trigger_bit.multiply(
            ever_encountered_a_source_event,
            ctx.narrow(&ZeroOutTriggerStep::DidTriggerGetAttributed),
            record_id,
        ),
        is_trigger_event_within_attribution_window(
            ctx.narrow(&ZeroOutTriggerStep::CheckAttributionWindow),
            record_id,
            attribution_window_seconds,
            trigger_event_timestamp,
            source_event_timestamp,
        ),
    )
    .await?;

    // save 1 multiplication if there is no attribution window
    let zero_out_flag = if attribution_window_seconds.is_some() {
        let c = ctx.narrow(&ZeroOutTriggerStep::AttributedEventCheckFlag);
        did_trigger_get_attributed
            .multiply(&is_trigger_within_window, c, record_id)
            .await?
    } else {
        did_trigger_get_attributed.clone()
    };

    select(
        ctx,
        record_id,
        &zero_out_flag,
        trigger_value,
        &Replicated::<TV>::ZERO,
    )
    .await
}

/// If the `attribution_window_seconds` is not `None`, we calculate the time
/// difference between the trigger event and the most recent source event, and
/// returns a secret-shared bit indicating if the trigger event is within the
/// attribution window.
async fn is_trigger_event_within_attribution_window<C, TS>(
    ctx: C,
    record_id: RecordId,
    attribution_window_seconds: Option<NonZeroU32>,
    trigger_event_timestamp: &Replicated<TS>,
    source_event_timestamp: &Replicated<TS>,
) -> Result<Replicated<Boolean>, Error>
where
    C: Context,
    TS: BooleanArray + U128Conversions,
    Replicated<Boolean>: BooleanProtocols<C>,
{
    if let Some(attribution_window_seconds) = attribution_window_seconds {
        assert!(
            TS::BITS <= ThirtyTwoBitStep::BITS,
            "ThirtyTwoBitStep is not large enough to accomodate this subtraction"
        );
        let time_delta_bits = integer_sub::<_, ThirtyTwoBitStep>(
            ctx.narrow(&WindowStep::ComputeTimeDelta),
            record_id,
            &trigger_event_timestamp.to_bits(),
            &source_event_timestamp.to_bits(),
        )
        .await?;

        let attribution_window_bits = BitDecomposed::decompose(TS::BITS, |i| {
            Replicated::share_known_value(
                &ctx,
                Boolean::truncate_from((attribution_window_seconds.get() >> i) & 0x1),
            )
        });

        let time_delta_gt_attribution_window = compare_gt::<_, ThirtyTwoBitStep, 1>(
            ctx.narrow(&WindowStep::CompareTimeDeltaToAttributionWindow),
            record_id,
            &time_delta_bits,
            &attribution_window_bits,
        )
        .await?;
        Ok(time_delta_gt_attribution_window.not())
    } else {
        // if there is no attribution window, then all trigger events are attributed
        Ok(Replicated::share_known_value(&ctx, Boolean::ONE))
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
async fn compute_capped_trigger_value<C, TV>(
    ctx: C,
    record_id: RecordId,
    is_saturated: &Replicated<Boolean>,
    is_saturated_and_prev_row_not_saturated: &Replicated<Boolean>,
    prev_row_diff_to_cap: &Replicated<TV>,
    attributed_trigger_value: &Replicated<TV>,
) -> Result<Replicated<TV>, Error>
where
    C: Context,
    TV: BooleanArray + U128Conversions,
    Replicated<TV>: BooleanArrayMul<C>,
{
    let narrowed_ctx1 =
        ctx.narrow(&PerRowStep::ComputedCappedAttributedTriggerValueNotSaturatedCase);
    let narrowed_ctx2 =
        ctx.narrow(&PerRowStep::ComputedCappedAttributedTriggerValueJustSaturatedCase);

    let attributed_trigger_value_or_zero = select(
        narrowed_ctx1,
        record_id,
        is_saturated,
        &Replicated::new(<TV as SharedValue>::ZERO, <TV as SharedValue>::ZERO),
        attributed_trigger_value,
    )
    .await?;

    select(
        narrowed_ctx2,
        record_id,
        is_saturated_and_prev_row_not_saturated,
        prev_row_diff_to_cap,
        &attributed_trigger_value_or_zero,
    )
    .await
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::num::NonZeroU32;

    use super::{AttributionOutputs, PrfShardedIpaInputRow};
    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BooleanArray, BA16, BA20, BA3, BA5, BA8},
            Field, U128Conversions,
        },
        protocol::ipa_prf::prf_sharding::attribute_cap_aggregate,
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SharedValue,
            TransposeFrom,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<BK: SharedValue, TV: SharedValue, TS: SharedValue> {
        prf_of_match_key: u64,
        is_trigger_bit: Boolean,
        breakdown_key: BK,
        trigger_value: TV,
        timestamp: TS,
    }

    fn oprf_test_input<BK>(
        prf_of_match_key: u64,
        is_trigger: bool,
        breakdown_key: u8,
        trigger_value: u8,
    ) -> PreShardedAndSortedOPRFTestInput<BK, BA3, BA20>
    where
        BK: SharedValue + U128Conversions,
    {
        oprf_test_input_with_timestamp(
            prf_of_match_key,
            is_trigger,
            breakdown_key,
            trigger_value,
            0,
        )
    }

    fn oprf_test_input_with_timestamp<BK>(
        prf_of_match_key: u64,
        is_trigger: bool,
        breakdown_key: u8,
        trigger_value: u8,
        timestamp: u32,
    ) -> PreShardedAndSortedOPRFTestInput<BK, BA3, BA20>
    where
        BK: SharedValue + U128Conversions,
    {
        let is_trigger_bit = if is_trigger {
            Boolean::ONE
        } else {
            Boolean::ZERO
        };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            breakdown_key: BK::truncate_from(breakdown_key),
            trigger_value: BA3::truncate_from(trigger_value),
            timestamp: BA20::truncate_from(timestamp),
        }
    }

    #[cfg(all(test, any(unit_test, feature = "shuttle")))]
    #[derive(Debug, Clone, Ord, PartialEq, PartialOrd, Eq)]
    pub struct PreAggregationTestOutputInDecimal {
        pub attributed_breakdown_key: u128,
        pub capped_attributed_trigger_value: u128,
    }

    #[cfg(all(test, any(unit_test, feature = "shuttle")))]
    impl<BK, TV, TS> IntoShares<PrfShardedIpaInputRow<BK, TV, TS>>
        for PreShardedAndSortedOPRFTestInput<BK, TV, TS>
    where
        BK: SharedValue + IntoShares<Replicated<BK>>,
        TV: SharedValue + IntoShares<Replicated<TV>>,
        TS: SharedValue + IntoShares<Replicated<TS>>,
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
                    sort_key: Replicated::ZERO,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit1,
                    breakdown_key: breakdown_key1,
                    trigger_value: trigger_value1,
                    timestamp: timestamp1,
                    sort_key: Replicated::ZERO,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit2,
                    breakdown_key: breakdown_key2,
                    trigger_value: trigger_value2,
                    timestamp: timestamp2,
                    sort_key: Replicated::ZERO,
                },
            ]
        }
    }

    #[cfg(all(test, any(unit_test, feature = "shuttle")))]
    impl<BK, TV> Reconstruct<PreAggregationTestOutputInDecimal>
        for [&AttributionOutputs<Replicated<BK>, Replicated<TV>>; 3]
    where
        BK: BooleanArray + U128Conversions,
        TV: BooleanArray + U128Conversions,
    {
        fn reconstruct(&self) -> PreAggregationTestOutputInDecimal {
            let [s0, s1, s2] = self;
            let bk_key_bits = [
                s0.attributed_breakdown_key_bits.clone(),
                s1.attributed_breakdown_key_bits.clone(),
                s2.attributed_breakdown_key_bits.clone(),
            ]
            .reconstruct();
            let capped_attributed_tv = [
                s0.capped_attributed_trigger_value.clone(),
                s1.capped_attributed_trigger_value.clone(),
                s2.capped_attributed_trigger_value.clone(),
            ]
            .reconstruct();

            PreAggregationTestOutputInDecimal {
                attributed_breakdown_key: bk_key_bits.as_u128(),
                capped_attributed_trigger_value: capped_attributed_tv.as_u128(),
            }
        }
    }

    #[test]
    fn semi_honest_aggregation_capping_attribution() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA5, BA3, BA20>> = vec![
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

            let histogram = [3, 3, 2, 2, 1, 1, 1, 1];

            let result: [Vec<Replicated<BA16>>; 3] = world
                .malicious(records.into_iter(), |ctx, input_rows| async move {
                    Vec::transposed_from(
                        &attribute_cap_aggregate::<_, BA5, BA3, BA16, BA20, 5, 32>(
                            ctx, input_rows, None, &histogram,
                        )
                        .await
                        .unwrap(),
                    )
                })
                .await
                .map(Result::unwrap);
            let result_reconstructed: Vec<BA16> = result.reconstruct();
            assert_eq!(
                result_reconstructed
                    .iter()
                    .map(U128Conversions::as_u128)
                    .collect::<Vec<_>>(),
                &expected
            );
        });
    }
    #[test]
    fn semi_honest_aggregation_capping_attribution_with_attribution_window() {
        const ATTRIBUTION_WINDOW_SECONDS: u32 = 200;

        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA5, BA3, BA20>> = vec![
                /* First User */
                oprf_test_input_with_timestamp(123, false, 17, 0, 1),
                oprf_test_input_with_timestamp(123, true, 0, 7, 200), // tsΔ = 199, attributed to 17
                oprf_test_input_with_timestamp(123, false, 20, 0, 200),
                oprf_test_input_with_timestamp(123, true, 0, 3, 300), // tsΔ = 100, attributed to 20
                /* Second User */
                oprf_test_input_with_timestamp(234, false, 12, 0, 0),
                oprf_test_input_with_timestamp(234, true, 0, 5, 200), // tsΔ = 200, attributed to 12
                /* Third User */
                oprf_test_input_with_timestamp(345, false, 20, 0, 0),
                oprf_test_input_with_timestamp(345, true, 0, 3, 100), // tsΔ = 100, attributed to 20
                oprf_test_input_with_timestamp(345, false, 18, 0, 200),
                oprf_test_input_with_timestamp(345, false, 12, 0, 300),
                oprf_test_input_with_timestamp(345, true, 0, 3, 400), // tsΔ = 100, attributed to 12
                oprf_test_input_with_timestamp(345, true, 0, 3, 499), // tsΔ = 199, attributed to 12
                oprf_test_input_with_timestamp(345, true, 0, 3, 501), // tsΔ = 201, not attributed
                oprf_test_input_with_timestamp(345, true, 0, 3, 700), // tsΔ = 400, not attributed
            ];

            let mut expected = [0_u128; 32];
            expected[12] = 11;
            expected[17] = 7;
            expected[20] = 6;

            let histogram = [3, 3, 2, 2, 1, 1, 1, 1];

            let result: [Vec<Replicated<BA16>>; 3] = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    Vec::transposed_from(
                        &attribute_cap_aggregate::<_, BA5, BA3, BA16, BA20, 5, 32>(
                            ctx,
                            input_rows,
                            NonZeroU32::new(ATTRIBUTION_WINDOW_SECONDS),
                            &histogram,
                        )
                        .await
                        .unwrap(),
                    )
                })
                .await
                .map(Result::unwrap);
            let result_reconstructed: Vec<BA16> = result.reconstruct();
            assert_eq!(
                result_reconstructed
                    .iter()
                    .map(U128Conversions::as_u128)
                    .collect::<Vec<_>>(),
                &expected
            );
        });
    }

    #[test]
    fn capping_bugfix() {
        const HISTOGRAM: [usize; 10] = [5, 5, 5, 5, 5, 5, 5, 2, 1, 1];

        run(|| async move {
            let world = TestWorld::default();

            #[allow(clippy::items_after_statements)]
            type SaturatingSumType = BA5;

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA8, BA3, BA20>> = vec![
                /* First User (perfectly saturates, then one extra) */
                oprf_test_input(10_251_308_645, false, 218, 0),
                oprf_test_input(10_251_308_645, true, 0, 3), // running-sum = 3
                oprf_test_input(10_251_308_645, true, 0, 3), // running-sum = 6
                oprf_test_input(10_251_308_645, true, 0, 5), // running-sum = 11
                oprf_test_input(10_251_308_645, true, 0, 6), // running-sum = 17
                oprf_test_input(10_251_308_645, true, 0, 1), // running-sum = 18
                oprf_test_input(10_251_308_645, true, 0, 2), // running-sum = 20
                oprf_test_input(10_251_308_645, true, 0, 6), // running-sum = 26
                oprf_test_input(10_251_308_645, true, 0, 6), // running-sum = 32
                // This next record should get zeroed out due to the per-user cap of 32
                oprf_test_input(10_251_308_645, true, 0, 6), // running-sum = 38
                /* Second User (imperfectly saturates, then a few extra) */
                oprf_test_input(1, false, 53, 0),
                oprf_test_input(1, true, 0, 7), // running-sum = 7
                oprf_test_input(1, true, 0, 7), // running-sum = 14
                oprf_test_input(1, true, 0, 7), // running-sum = 21
                oprf_test_input(1, true, 0, 7), // running-sum = 28
                // This record should be partially capped
                oprf_test_input(1, true, 0, 7), // running-sum = 35
                // The next two records should be fully capped
                oprf_test_input(1, true, 0, 7), // running-sum = 42
                oprf_test_input(1, true, 0, 7), // running-sum = 49
                /* Third User (perfectly saturates, no extras) */
                oprf_test_input(2, false, 12, 0),
                oprf_test_input(2, true, 0, 6), // running-sum = 6
                oprf_test_input(2, true, 0, 4), // running-sum = 10
                oprf_test_input(2, true, 0, 6), // running-sum = 16
                oprf_test_input(2, true, 0, 4), // running-sum = 20
                oprf_test_input(2, true, 0, 6), // running-sum = 26
                oprf_test_input(2, true, 0, 6), // running-sum = 32
                /* Fourth User (imperfectly saturates, no extras) */
                oprf_test_input(3, false, 78, 0),
                oprf_test_input(3, true, 0, 7), // running-sum = 7
                oprf_test_input(3, true, 0, 6), // running-sum = 13
                oprf_test_input(3, true, 0, 5), // running-sum = 18
                oprf_test_input(3, true, 0, 7), // running-sum = 25
                oprf_test_input(3, true, 0, 6), // running-sum = 31
                // The next row should be partially capped
                oprf_test_input(3, true, 0, 5), // running-sum = 36
                /* Fifth User (does not saturate) */
                oprf_test_input(4, false, 44, 0),
                oprf_test_input(4, true, 0, 4), // running-sum = 4
                oprf_test_input(4, true, 0, 5), // running-sum = 9
                oprf_test_input(4, true, 0, 6), // running-sum = 15
                oprf_test_input(4, true, 0, 5), // running-sum = 20
                oprf_test_input(4, true, 0, 4), // running-sum = 24
                oprf_test_input(4, true, 0, 7), // running-sum = 31
            ];

            let mut expected = [0_u128; 256];
            expected[218] = 1 << SaturatingSumType::BITS; // per-user cap is 2^5
            expected[53] = 1 << SaturatingSumType::BITS; // per-user cap is 2^5
            expected[12] = 1 << SaturatingSumType::BITS; // per-user cap is 2^5
            expected[78] = 1 << SaturatingSumType::BITS; // per-user cap is 2^5
            expected[44] = 31; // The 5th user did not saturate

            let result: [Vec<Replicated<BA8>>; 3] = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    Vec::transposed_from(
                        &attribute_cap_aggregate::<
                            _,
                            BA8,
                            BA3,
                            BA8,
                            BA20,
                            { SaturatingSumType::BITS as usize },
                            256,
                        >(ctx, input_rows, None, &HISTOGRAM)
                        .await
                        .unwrap(),
                    )
                })
                .await
                .map(Result::unwrap);
            let result_reconstructed: Vec<BA8> = result.reconstruct();
            assert_eq!(
                result_reconstructed
                    .iter()
                    .map(U128Conversions::as_u128)
                    .collect::<Vec<_>>(),
                &expected
            );
        });
    }
}
