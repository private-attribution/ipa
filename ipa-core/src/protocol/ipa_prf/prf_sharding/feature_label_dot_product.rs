use std::{
    convert::Infallible,
    iter::{self, zip},
};

use futures::stream;
use futures_util::{future::try_join, stream::unfold, Stream, StreamExt};

use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{boolean::Boolean, boolean_array::BooleanArray, Expand, Field, U128Conversions},
    helpers::{repeat_n, stream::TryFlattenItersExt, TotalRecords},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        boolean::{and::bool_and_8_bit, or::or},
        context::Context,
        ipa_prf::{
            aggregation::aggregate_values,
            prf_sharding::step::{FeatureLabelDotProductStep as Step, UserNthRowStep},
        },
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            semi_honest::{AdditiveShare as Replicated, AdditiveShare},
            ReplicatedSecretSharing,
        },
        BitDecomposed, FieldSimd, SharedValue, TransposeFrom, Vectorizable,
    },
    seq_join::seq_join,
};

pub struct PrfShardedIpaInputRow<FV: SharedValue, const B: usize> {
    prf_of_match_key: u64,
    is_trigger_bit: Replicated<Boolean>,
    feature_vector: [Replicated<FV>; B],
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
    pub async fn compute_row_with_previous<'ctx, C, FV, const B: usize>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<FV, B>,
    ) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
    where
        C: Context,
        Boolean: FieldSimd<B>,
        Replicated<Boolean, B>: BooleanProtocols<C, B>,
        Replicated<Boolean>: SecureMul<C>,
        FV: SharedValue,
        BitDecomposed<Replicated<Boolean, B>>:
            for<'a> TransposeFrom<&'a [Replicated<FV>; B], Error = Infallible>,
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

        let condition = Replicated::new_arr(
            <Boolean as Vectorizable<B>>::Array::expand(&capped_label.left()),
            <Boolean as Vectorizable<B>>::Array::expand(&capped_label.right()),
        );
        let mut bit_decomposed_output = BitDecomposed::new(iter::empty());
        bit_decomposed_output
            .transpose_from(&input_row.feature_vector)
            .unwrap_infallible();
        let capped_attributed_feature_vector = bool_and_8_bit(
            ctx,
            record_id,
            &bit_decomposed_output,
            repeat_n(&condition, FV::BITS.try_into().unwrap()),
        )
        .await;

        self.ever_encountered_a_trigger_event = ever_encountered_a_trigger_event;
        self.is_saturated = updated_is_saturated;

        capped_attributed_feature_vector
    }
}

fn set_up_contexts<C>(root_ctx: &C, users_having_n_records: &[usize]) -> Result<Vec<C>, Error>
where
    C: Context,
{
    let mut context_per_row_depth = Vec::with_capacity(users_having_n_records.len());
    for (row_number, num_users_having_that_row_number) in users_having_n_records.iter().enumerate()
    {
        if row_number == 0 {
            // no multiplications needed for each user's row 0. No context needed
        } else {
            let total_records = TotalRecords::specified(*num_users_having_that_row_number)?;
            let ctx_for_row_number = root_ctx
                .narrow(&UserNthRowStep::from(row_number))
                .set_total_records(total_records);
            context_per_row_depth.push(ctx_for_row_number);
        }
    }
    Ok(context_per_row_depth)
}

///
/// Takes an input stream of `PrfShardedIpaInputRecordRow` which is assumed to have all records with a given PRF adjacent
/// and converts it into a stream of vectors of `PrfShardedIpaInputRecordRow` having the same PRF.
///
fn chunk_rows_by_user<FV, IS, const B: usize>(
    input_stream: IS,
    first_row: PrfShardedIpaInputRow<FV, B>,
) -> impl Stream<Item = Vec<PrfShardedIpaInputRow<FV, B>>>
where
    FV: SharedValue,
    IS: Stream<Item = PrfShardedIpaInputRow<FV, B>> + Unpin,
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
/// Rather than calculate this distribution within this function (challenging to do while streaming), at present the caller must pass this in.
///
/// The count at a given index indicates the number of users having at least that many rows of data.
///
/// Example:
///   If the input is from 3 users,
///     - the first having 2 records
///     - the second having 4 records
///     - the third having 6 records
///   Then the data-structure that should be provided for the `users_having_n_records` is:
///     - [3, 3, 2, 2, 1, 1]
///
/// # Errors
/// Propagates errors from multiplications
/// # Panics
/// Propagates errors from multiplications
pub async fn compute_feature_label_dot_product<'ctx, C, TV, HV, const B: usize>(
    sh_ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<TV, B>>,
    users_having_n_records: &[usize],
) -> Result<[Replicated<HV>; B], Error>
where
    C: Context,
    Boolean: FieldSimd<B>,
    Replicated<Boolean>: SecureMul<C>,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    TV: SharedValue,
    HV: BooleanArray + U128Conversions,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    // Get the validator and context to use for Boolean multiplication operations
    let binary_m_ctx = sh_ctx.narrow(&Step::BinaryValidator);

    // Tricky hacks to work around the limitations of our current infrastructure
    // There will be 0 outputs for users with just one row.
    // There will be 1 output for users with at least 2 rows.
    // So we just use the number of users having at least 2 rows.
    let num_outputs = users_having_n_records[1];
    let ctx_for_row_number = set_up_contexts(&binary_m_ctx, users_having_n_records)?;

    // Chunk the incoming stream of records into stream of vectors of records with the same PRF
    let mut input_stream = stream::iter(input_rows);
    let Some(first_row) = input_stream.next().await else {
        return Ok([Replicated::<HV>::ZERO; B]);
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
    // The call to `try_flatten_iters` only serves to eliminate the "Option" wrapping, and filter out `None` elements
    let flattened_stream = Box::pin(
        seq_join(sh_ctx.active_work(), stream::iter(chunked_user_results)).try_flatten_iters(),
    );
    let aggregated_result: BitDecomposed<AdditiveShare<Boolean, B>> =
        aggregate_values::<_, HV, B>(binary_m_ctx, flattened_stream, num_outputs).await?;

    let transposed_aggregated_result: Vec<Replicated<HV>> =
        Vec::transposed_from(&aggregated_result)?;

    Ok(transposed_aggregated_result.try_into().unwrap())
}

async fn evaluate_per_user_attribution_circuit<'ctx, C, FV, const B: usize>(
    ctx_for_row_number: Vec<C>,
    record_id: RecordId,
    rows_for_user: Vec<PrfShardedIpaInputRow<FV, B>>,
) -> Result<Option<BitDecomposed<Replicated<Boolean, B>>>, Error>
where
    C: Context,
    Boolean: FieldSimd<B>,
    Replicated<Boolean>: SecureMul<C>,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    FV: SharedValue,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<FV>; B], Error = Infallible>,
{
    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(None);
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs = initialize_new_device_attribution_variables(first_row);

    //
    // Since compute_row_with_previous ensures there will be *at most* a single non-zero contribution
    // from each user, we can just add all of the outputs together for any given user.
    // There is no need for any carries since we are always adding zero to the single contribution.
    let mut output = BitDecomposed::new(repeat_n(Replicated::ZERO, FV::BITS.try_into().unwrap()));

    // skip the first row as it requires no multiplications
    // no context was created for the first row
    for (row, ctx) in zip(rows_for_user.iter().skip(1), ctx_for_row_number.into_iter()) {
        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous::<_, FV, B>(ctx, record_id, row)
            .await?;

        zip(output.iter_mut(), capped_attribution_outputs).for_each(|(x, y)| *x += y);
    }

    Ok(Some(output))
}

///
/// Upon encountering the first row of data from a new user (as distinguished by a different OPRF of the match key)
/// this function encapsulates the variables that must be initialized. No communication is required for this first row.
///
fn initialize_new_device_attribution_variables<FV, const B: usize>(
    input_row: &PrfShardedIpaInputRow<FV, B>,
) -> InputsRequiredFromPrevRow
where
    FV: SharedValue,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_trigger_event: input_row.is_trigger_bit.clone(),
        is_saturated: Replicated::ZERO,
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::iter::zip;

    use rand::thread_rng;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA16, BA8},
            Field, U128Conversions,
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

    struct PreShardedAndSortedOPRFTestInput<FV, const B: usize> {
        prf_of_match_key: u64,
        is_trigger_bit: Boolean,
        feature_vector: [FV; B],
    }

    fn test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        feature_vector: [u8; 32],
    ) -> PreShardedAndSortedOPRFTestInput<BA8, 32> {
        let is_trigger_bit = if is_trigger {
            Boolean::ONE
        } else {
            <Boolean as SharedValue>::ZERO
        };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            feature_vector: feature_vector.map(BA8::truncate_from),
        }
    }

    impl<FV, const B: usize> IntoShares<PrfShardedIpaInputRow<FV, B>>
        for PreShardedAndSortedOPRFTestInput<FV, B>
    where
        FV: SharedValue + IntoShares<Replicated<FV>>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [PrfShardedIpaInputRow<FV, B>; 3] {
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

    const ZERO_FEATURES: [u8; 32] = [0; 32];

    #[test]
    fn semi_honest() {
        run(|| async move {
            let world = TestWorld::default();

            let mut rng = thread_rng();
            let attributed_features: [[u8; 32]; 3] =
                [[rng.gen(); 32], [rng.gen(); 32], [rng.gen(); 32]];

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA8, 32>> = vec![
                /* First User */
                test_input(123, true, ZERO_FEATURES), // trigger
                test_input(123, false, attributed_features[0]), // this source DOES receive attribution
                test_input(123, true, ZERO_FEATURES),           // trigger
                test_input(123, false, [rng.gen(); 32]), // this source does not receive attribution (capped)
                /* Second User */
                test_input(234, true, ZERO_FEATURES), // trigger
                test_input(234, false, attributed_features[1]), // this source DOES receive attribution
                /* Third User */
                test_input(345, true, ZERO_FEATURES), // trigger
                test_input(345, true, ZERO_FEATURES), // trigger
                test_input(345, true, ZERO_FEATURES), // trigger
                test_input(345, true, ZERO_FEATURES), // trigger
                test_input(345, false, attributed_features[2]), // this source DOES receive attribution
                test_input(345, false, [rng.gen(); 32]), // this source does not receive attribution (capped)
                test_input(345, true, ZERO_FEATURES),    // trigger
                test_input(345, false, [rng.gen(); 32]), // this source does not receive attribution (capped)
                /* Fourth User */
                test_input(456, false, [rng.gen(); 32]), // this source does NOT receive any attribution because this user has no trigger events
            ];

            let expected: [u128; 32] =
                attributed_features
                    .into_iter()
                    .fold([0_u128; 32], |mut acc, x| {
                        zip(acc.iter_mut(), x).for_each(|(a, b)| *a += u128::from(b));
                        acc
                    });

            let users_having_n_records = vec![4, 3, 2, 2, 1, 1, 1, 1];

            let result = world
                .upgraded_semi_honest(records.into_iter(), |ctx, input_rows| {
                    let h = users_having_n_records.as_slice();
                    async move {
                        compute_feature_label_dot_product::<_, BA8, BA16, 32>(ctx, input_rows, h)
                            .await
                            .unwrap()
                    }
                })
                .await
                .reconstruct()
                .iter()
                .map(U128Conversions::as_u128)
                .collect::<Vec<_>>();

            assert_eq!(&result, &expected);
        });
    }
}
