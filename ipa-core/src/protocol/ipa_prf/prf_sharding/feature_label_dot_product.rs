use std::iter::{self, zip};

use futures::{stream, TryStreamExt};
use futures_util::{future::try_join, stream::unfold, Stream, StreamExt};
use ipa_macros::Step;

use crate::{
    error::{Error, LengthError},
    ff::{boolean::Boolean, CustomArray, Field, U128Conversions},
    helpers::stream::TryFlattenItersExt,
    protocol::{
        basics::{select, BooleanArrayMul, BooleanProtocols, SecureMul, ShareKnownValue},
        boolean::or::or,
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::aggregation::aggregate_values,
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, FieldVectorizable, SharedValue, TransposeFrom,
    },
    seq_join::{seq_join, SeqJoin},
    sharding::NotSharded,
};

pub struct PrfShardedIpaInputRow<FV: SharedValue + CustomArray<Element = Boolean>> {
    prf_of_match_key: u64,
    is_trigger_bit: Replicated<Boolean>,
    feature_vector: Replicated<FV>,
}

struct InputsRequiredFromPrevRow {
    ever_encountered_a_trigger_event: Replicated<Boolean>,
    is_saturated: Replicated<Boolean>,
}

impl InputsRequiredFromPrevRow {
    ///
    /// This function contains the main logic for the per-user attribution circuit.
    /// Multiple rows of data about a single user are processed in-order from newest to oldest.
    ///
    /// Summary:
    /// - Last touch attribution
    ///     - Every source event which has a subsequent trigger event receives attribution
    /// - Per user capping
    ///     - A cumulative count of "Source Events Receiving Attribution" is maintained
    ///     - Bitwise addition is used, and a single bit indicates if the sum is "saturated"
    ///     - The only available values for "cap" are powers of 2 (i.e. 1, 2, 4, 8, 16, 32, ...)
    ///     - Prior to saturation, feature vectors of source events receiving attribution contribute to the dot-product.
    ///     - All subsequent rows contribute zero
    /// - Outputs
    ///     - If a user has `N` input rows, they will generate `N-1` output rows. (The first row cannot possibly contribute any value to the output)
    ///     - Each output row is a vector, either the feature vector or zeroes.
    pub async fn compute_row_with_previous<'ctx, FV>(
        &mut self,
        ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<FV>,
    ) -> Result<Replicated<FV>, Error>
    where
        FV: SharedValue + CustomArray<Element = Boolean>,
        Replicated<FV>: BooleanArrayMul,
    {
        let share_of_one = Replicated::share_known_value(&ctx, Boolean::ONE);
        let is_source_event = &share_of_one - &input_row.is_trigger_bit;

        let (ever_encountered_a_trigger_event, did_source_get_attributed) = try_join(
            or(
                ctx.narrow(&Step::EverEncounteredTriggerEvent),
                record_id,
                &input_row.is_trigger_bit,
                &self.ever_encountered_a_trigger_event,
            ),
            is_source_event.multiply(
                &self.ever_encountered_a_trigger_event,
                ctx.narrow(&Step::DidSourceReceiveAttribution),
                record_id,
            ),
        )
        .await?;

        let (updated_is_saturated, capped_label) = try_join(
            or(
                ctx.narrow(&Step::ComputeSaturatingSum),
                record_id,
                &self.is_saturated,
                &did_source_get_attributed,
            ),
            did_source_get_attributed.multiply(
                &(share_of_one - &self.is_saturated),
                ctx.narrow(&Step::IsAttributedSourceAndPrevRowNotSaturated),
                record_id,
            ),
        )
        .await?;

        let capped_attributed_feature_vector = select(
            ctx.narrow(&Step::ComputedCappedFeatureVector),
            record_id,
            &capped_label,
            &input_row.feature_vector,
            &Replicated::<FV>::ZERO,
        )
        .await?;

        self.ever_encountered_a_trigger_event = ever_encountered_a_trigger_event;
        self.is_saturated = updated_is_saturated;

        Ok(capped_attributed_feature_vector)
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
pub(crate) enum Step {
    BinaryValidator,
    EverEncounteredTriggerEvent,
    DidSourceReceiveAttribution,
    ComputeSaturatingSum,
    IsAttributedSourceAndPrevRowNotSaturated,
    ComputedCappedFeatureVector,
}

fn set_up_contexts<C>(root_ctx: &C, histogram: &[usize]) -> Vec<C>
where
    C: Context,
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
fn chunk_rows_by_user<FV, IS>(
    input_stream: IS,
    first_row: PrfShardedIpaInputRow<FV>,
) -> impl Stream<Item = Vec<PrfShardedIpaInputRow<FV>>>
where
    FV: SharedValue + CustomArray<Element = Boolean>,
    IS: Stream<Item = PrfShardedIpaInputRow<FV>> + Unpin,
{
    unfold(Some((input_stream, first_row)), |state| async move {
        let (mut s, last_row) = state?;
        let last_row_prf = last_row.prf_of_match_key;
        let mut current_chunk = vec![last_row];
        while let Some(row) = s.next().await {
            if row.prf_of_match_key == last_row_prf {
                current_chunk.push(row);
            } else {
                return Some((current_chunk, Some((s, row))));
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
/// but with all of the records from a given user adjacent to one another, and in reverse time order (most recent event comes first).
///
/// This circuit will compute attribution, and per-user capping.
///
/// After those steps, source events to which trigger events were attributed will contribute their feature vectors to an aggregate
///
/// The aggregate is just the sum of all the feature vectors of source events which received attribution
///
/// This is useful for performing logistic regression: `https://github.com/patcg-individual-drafts/ipa/blob/main/logistic_regression.md`
///
/// Due to limitation in our infra, it's necessary to set the total number of records each channel will ever need to process.
/// The number of records each channel processes is a function of the distribution of number of records per user.
/// Rather than calculate this histogram within this function (challenging to do while streaming), at present the caller must pass this in.
///
/// The count at a given index indicates the number of users having at least that many rows of data.
///
/// Example:
///   If the input is from 3 users,
///     - the first having 2 records
///     - the second having 4 records
///     - the third having 6 records
///   Then the histogram that should be provided is:
///     - [3, 3, 2, 2, 1, 1]
///
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
pub async fn compute_feature_label_dot_product<'ctx, FV, OV, const B: usize>(
    sh_ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
    input_rows: Vec<PrfShardedIpaInputRow<FV>>,
    histogram: &[usize],
) -> Result<Vec<Replicated<OV>>, Error>
where
    FV: SharedValue + CustomArray<Element = Boolean>,
    OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<B> + FieldVectorizable<B, ArrayAlias = FV>,
    Replicated<FV>: BooleanArrayMul,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, Boolean, B>,
    Vec<Replicated<OV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    assert_eq!(<FV as SharedValue>::BITS, u32::try_from(B).unwrap());

    // Get the validator and context to use for Boolean multiplication operations
    let binary_m_ctx = sh_ctx.narrow(&Step::BinaryValidator);

    // Tricky hacks to work around the limitations of our current infrastructure
    let num_outputs = input_rows.len() - histogram[0];
    let ctx_for_row_number = set_up_contexts(&binary_m_ctx, histogram);

    // Chunk the incoming stream of records into stream of vectors of records with the same PRF
    let mut input_stream = stream::iter(input_rows);
    let Some(first_row) = input_stream.next().await else {
        return Ok(vec![]);
    };
    let rows_chunked_by_user = chunk_rows_by_user(input_stream, first_row);

    let mut collected = rows_chunked_by_user.collect::<Vec<_>>().await;
    collected.sort_by(|a, b| std::cmp::Ord::cmp(&b.len(), &a.len()));

    let chunked_user_results =
        collected
            .into_iter()
            .enumerate()
            .map(|(record_id, rows_for_user)| {
                let num_user_rows = rows_for_user.len();
                let contexts = ctx_for_row_number[..num_user_rows - 1].to_owned();

                evaluate_per_user_attribution_circuit(
                    contexts,
                    RecordId::from(record_id),
                    rows_for_user,
                )
            });

    // Execute all of the async futures (sequentially), and flatten the result
    let flattened_stream = Box::pin(
        seq_join(sh_ctx.active_work(), stream::iter(chunked_user_results))
            .try_flatten_iters()
            .map_ok(|value| {
                BitDecomposed::new(iter::once(Replicated::new_arr(value.left(), value.right())))
            }),
    );

    aggregate_values::<_, B>(binary_m_ctx, flattened_stream, num_outputs).await
}

async fn evaluate_per_user_attribution_circuit<FV>(
    ctx_for_row_number: Vec<UpgradedSemiHonestContext<'_, NotSharded, Boolean>>,
    record_id: RecordId,
    rows_for_user: Vec<PrfShardedIpaInputRow<FV>>,
) -> Result<Vec<Replicated<FV>>, Error>
where
    FV: SharedValue + CustomArray<Element = Boolean>,
    Replicated<FV>: BooleanArrayMul,
{
    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(Vec::new());
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs = initialize_new_device_attribution_variables(first_row);

    let mut output = Vec::with_capacity(rows_for_user.len() - 1);
    // skip the first row as it requires no multiplications
    // no context was created for the first row
    for (row, ctx) in zip(rows_for_user.iter().skip(1), ctx_for_row_number.into_iter()) {
        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(ctx, record_id, row)
            .await?;

        output.push(capped_attribution_outputs);
    }

    Ok(output)
}

///
/// Upon encountering the first row of data from a new user (as distinguished by a different OPRF of the match key)
/// this function encapsulates the variables that must be initialized. No communication is required for this first row.
///
fn initialize_new_device_attribution_variables<FV>(
    input_row: &PrfShardedIpaInputRow<FV>,
) -> InputsRequiredFromPrevRow
where
    FV: SharedValue + CustomArray<Element = Boolean>,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_trigger_event: input_row.is_trigger_bit.clone(),
        is_saturated: Replicated::ZERO,
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA32, BA8},
            CustomArray, Field, U128Conversions,
        },
        protocol::ipa_prf::prf_sharding::feature_label_dot_product::{
            compute_feature_label_dot_product, PrfShardedIpaInputRow,
        },
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SharedValue,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<FV: CustomArray<Element = Boolean>> {
        prf_of_match_key: u64,
        is_trigger_bit: Boolean,
        feature_vector: FV,
    }

    fn test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        feature_vector: u32,
    ) -> PreShardedAndSortedOPRFTestInput<BA32> {
        let is_trigger_bit = if is_trigger {
            Boolean::ONE
        } else {
            <Boolean as SharedValue>::ZERO
        };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            feature_vector: BA32::truncate_from(feature_vector),
        }
    }

    impl<FV> IntoShares<PrfShardedIpaInputRow<FV>> for PreShardedAndSortedOPRFTestInput<FV>
    where
        FV: SharedValue + CustomArray<Element = Boolean> + IntoShares<Replicated<FV>>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [PrfShardedIpaInputRow<FV>; 3] {
            let PreShardedAndSortedOPRFTestInput {
                prf_of_match_key,
                is_trigger_bit,
                feature_vector,
            } = self;

            let [is_trigger_bit0, is_trigger_bit1, is_trigger_bit2] =
                is_trigger_bit.share_with(rng);
            let [feature_vector0, feature_vector1, feature_vector2] =
                feature_vector.share_with(rng);

            [
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit0,
                    feature_vector: feature_vector0,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit1,
                    feature_vector: feature_vector1,
                },
                PrfShardedIpaInputRow {
                    prf_of_match_key,
                    is_trigger_bit: is_trigger_bit2,
                    feature_vector: feature_vector2,
                },
            ]
        }
    }

    #[test]
    fn semi_honest() {
        run(|| async move {
            let world = TestWorld::default();

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA32>> = vec![
                /* First User */
                test_input(123, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(123, false, 0b1101_0100_1111_0001_0111_0010_1010_1011), // this source DOES receive attribution
                test_input(123, true, 0b0000_0000_0000_0000_0000_0000_0000_0000),  // trigger
                test_input(123, false, 0b0110_1101_0001_0100_1011_0100_1010_1001), // this source does not receive attribution (capped)
                /* Second User */
                test_input(234, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(234, false, 0b0001_1010_0011_0111_0110_0010_1111_0000), // this source DOES receive attribution
                /* Third User */
                test_input(345, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(345, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(345, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(345, true, 0b0000_0000_0000_0000_0000_0000_0000_0000), // trigger
                test_input(345, false, 0b0111_0101_0001_0000_0111_0100_0101_0011), // this source DOES receive attribution
                test_input(345, false, 0b1001_1000_1011_1101_0100_0110_0001_0100), // this source does not receive attribution (capped)
                test_input(345, true, 0b0000_0000_0000_0000_0000_0000_0000_0000),  // trigger
                test_input(345, false, 0b1000_1001_0100_0011_0111_0010_0000_1101), // this source does not receive attribution (capped)
            ];

            let mut expected: [u128; 32] = [
                //     1101_0100_1111_0001_0111_0010_1010_1011
                //     0001_1010_0011_0111_0110_0010_1111_0000
                // +   0111_0101_0001_0000_0111_0100_0101_0011
                // -------------------------------------------
                //     1213_1211_1123_0112_0332_0120_2222_1022
                1, 2, 1, 3, 1, 2, 1, 1, 1, 1, 2, 3, 0, 1, 1, 2, 0, 3, 3, 2, 0, 1, 2, 0, 2, 2, 2, 2,
                1, 0, 2, 2,
            ];
            expected.reverse(); // convert to little-endian order

            let histogram = vec![3, 3, 2, 2, 1, 1, 1, 1];

            let result: Vec<BA8> = world
                .upgraded_semi_honest(records.into_iter(), |ctx, input_rows| {
                    let h = histogram.as_slice();
                    async move {
                        compute_feature_label_dot_product::<BA32, BA8, 32>(ctx, input_rows, h)
                            .await
                            .unwrap()
                    }
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }
}
