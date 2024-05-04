use std::iter::{self, zip};

use futures::{stream, TryStreamExt};
use futures_util::{future::try_join, stream::unfold, Stream, StreamExt};
use generic_array::{functional::FunctionalSequence, sequence::GenericSequence, ArrayLength, GenericArray};
use ipa_macros::Step;

use crate::{
    error::{Error, LengthError},
    ff::{boolean::Boolean, boolean_array::{BA16, BA32, BA8}, ArrayAccess, CustomArray, Field, U128Conversions},
    helpers::stream::TryFlattenItersExt,
    protocol::{
        basics::{select, BooleanArrayMul, BooleanProtocols, SecureMul, ShareKnownValue},
        boolean::or::or,
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::aggregation::aggregate_values,
        RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing}, BitDecomposed, FieldSimd, FieldVectorizable, SharedValue, SharedValueArray, TransposeFrom, Vectorizable
    },
    seq_join::{seq_join, SeqJoin},
    sharding::NotSharded,
};

pub struct PrfShardedIpaInputRow<M: ArrayLength, FV: SharedValue + CustomArray<Element = Boolean>> {
    prf_of_match_key: u64,
    is_trigger_bit: Replicated<Boolean>,
    feature_vector: GenericArray<Replicated<FV>, M>,
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
    pub async fn compute_row_with_previous<C, M, FV>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<M, FV>,
    ) -> Result<GenericArray<Replicated<FV>, M>, Error>
    where
        C: Context,
        FV: SharedValue + CustomArray<Element = Boolean>,
        Replicated<FV>: BooleanArrayMul,
        M: ArrayLength,
        Replicated<Boolean>: SecureMul<C>,
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

        let feature_contexts = (0..).map(|i| ctx.narrow(&Step::ComputedCappedFeatureVector(i)));
        let capped_label_ref = &capped_label;
        let capped_attributed_feature_vector = ctx
            .parallel_join(zip(feature_contexts, &input_row.feature_vector).map(
                |(c, feature)| async move {
                    select(
                        c,
                        record_id,
                        capped_label_ref,
                        feature,
                        &Replicated::<FV>::ZERO,
                    )
                    .await
                },
            ))
            .await?;

        self.ever_encountered_a_trigger_event = ever_encountered_a_trigger_event;
        self.is_saturated = updated_is_saturated;

        Ok(GenericArray::from_iter(
            capped_attributed_feature_vector.into_iter(),
        ))
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
    EverEncounteredTriggerEvent,
    DidSourceReceiveAttribution,
    ComputeSaturatingSum,
    IsAttributedSourceAndPrevRowNotSaturated,
    #[dynamic(1024)]
    ComputedCappedFeatureVector(usize),
    #[dynamic(32)]
    AggregatePass(usize),
    #[dynamic(64)]
    AggregateFeatureIndex(usize),
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
fn chunk_rows_by_user<FV, IS, M>(
    input_stream: IS,
    first_row: PrfShardedIpaInputRow<M, FV>,
) -> impl Stream<Item = Vec<PrfShardedIpaInputRow<M, FV>>>
where
    FV: SharedValue + CustomArray<Element = Boolean>,
    IS: Stream<Item = PrfShardedIpaInputRow<M, FV>> + Unpin,
    M: ArrayLength,
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
pub async fn compute_feature_label_dot_product<C, M /*FV, FVS*/, const B: usize>(
    ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<M, BA8>>,
    histogram: &[usize],
) -> Result<GenericArray<Replicated<BA16>, M>, Error>
where
    C: Context,
    // FV: SharedValue + CustomArray<Element = Boolean>,
    // FVS: SharedValue + CustomArray<Element = Boolean>,
    Replicated<BA8>: BooleanArrayMul,
    Replicated<Boolean>: SecureMul<C>,
    M: ArrayLength,
{
    // Tricky hacks to work around the limitations of our current infrastructure
    let num_outputs = histogram[0];
    let ctx_for_row_number = set_up_contexts(&ctx, histogram);

    // Chunk the incoming stream of records into stream of vectors of records with the same PRF
    let mut input_stream = stream::iter(input_rows);
    let Some(first_row) = input_stream.next().await else {
        return Ok(GenericArray::generate(|_| Replicated::<BA16>::ZERO));
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
        seq_join(ctx.active_work(), stream::iter(chunked_user_results))
            .map_ok(|value| {
                
                BitDecomposed::new(
                    (0..BA8::BITS).map(|bit| {
                        let mut packed_bits = Replicated::new(BA32::ZERO_ARRAY, BA32::ZERO_ARRAY);
                        for (i, feature) in value.iter().enumerate() {
                            packed_bits.set(i, feature.get(bit.try_into().unwrap()).unwrap());
                        }
                        packed_bits
                    })
                )                
            }),
    );

    let foo = aggregate_values::<BA16, B>(ctx, flattened_stream, num_outputs).await?;

    Ok(GenericArray::from_iter(foo))
}

async fn evaluate_per_user_attribution_circuit<C, M, FV>(
    ctx_for_row_number: Vec<C>,
    record_id: RecordId,
    rows_for_user: Vec<PrfShardedIpaInputRow<M, FV>>,
) -> Result<GenericArray<Replicated<FV>, M>, Error>
where
    C: Context,
    FV: SharedValue + CustomArray<Element = Boolean>,
    Replicated<FV>: BooleanArrayMul,
    Replicated<Boolean>: SecureMul<C>,
    M: ArrayLength,
{
    let mut output = GenericArray::<Replicated<FV>, M>::generate(|_| Replicated::<FV>::ZERO);

    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(output);
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs = initialize_new_device_attribution_variables(first_row);

    // skip the first row as it requires no multiplications
    // no context was created for the first row
    for (row, ctx) in zip(rows_for_user.iter().skip(1), ctx_for_row_number.into_iter()) {
        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(ctx, record_id, row)
            .await?;

        output = zip(output, capped_attribution_outputs)
            .map(|(x, y)| x + y)
            .collect();
    }

    Ok(output)
}

///
/// Upon encountering the first row of data from a new user (as distinguished by a different OPRF of the match key)
/// this function encapsulates the variables that must be initialized. No communication is required for this first row.
///
fn initialize_new_device_attribution_variables<M, FV>(
    input_row: &PrfShardedIpaInputRow<M, FV>,
) -> InputsRequiredFromPrevRow
where
    FV: SharedValue + CustomArray<Element = Boolean>,
    M: ArrayLength,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_trigger_event: input_row.is_trigger_bit.clone(),
        is_saturated: Replicated::ZERO,
    }
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use generic_array::{sequence::GenericSequence, ArrayLength, GenericArray};
    use typenum::U32;

    use crate::{
        ff::{boolean::Boolean, boolean_array::BA8, CustomArray, Field, U128Conversions},
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

    struct PreShardedAndSortedOPRFTestInput<FV: CustomArray<Element = Boolean>, M: ArrayLength> {
        prf_of_match_key: u64,
        is_trigger_bit: Boolean,
        feature_vector: GenericArray<FV, M>,
    }

    fn test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        feature_vector: [u8; 32],
    ) -> PreShardedAndSortedOPRFTestInput<BA8, U32> {
        let is_trigger_bit = if is_trigger {
            Boolean::ONE
        } else {
            <Boolean as SharedValue>::ZERO
        };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            feature_vector: GenericArray::<_, U32>::generate(|i| {
                BA8::truncate_from(feature_vector[i])
            }),
        }
    }

    impl<M, FV> IntoShares<PrfShardedIpaInputRow<M, FV>> for PreShardedAndSortedOPRFTestInput<FV, M>
    where
        FV: SharedValue + CustomArray<Element = Boolean> + IntoShares<Replicated<FV>>,
        M: ArrayLength,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [PrfShardedIpaInputRow<M, FV>; 3] {
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

            let records: Vec<PreShardedAndSortedOPRFTestInput<BA8, U32>> = vec![
                /* First User */
                test_input(
                    123,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    123,
                    false,
                    [
                        2, 8, 127, 4, 19, 33, 51, 92, 126, 22, 60, 12, 15, 201, 227, 56, 107, 40,
                        66, 29, 14, 42, 78, 99, 100, 48, 3, 5, 9, 91, 42, 198,
                    ],
                ), // this source DOES receive attribution
                test_input(
                    123,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    123,
                    false,
                    [
                        14, 12, 110, 210, 52, 3, 89, 32, 74, 28, 50, 216, 184, 163, 49, 211, 19,
                        162, 182, 244, 35, 8, 97, 23, 168, 9, 12, 68, 178, 234, 40, 196,
                    ],
                ), // this source does not receive attribution (capped)
                /* Second User */
                test_input(
                    234,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    234,
                    false,
                    [
                        227, 107, 125, 75, 50, 15, 115, 120, 49, 144, 160, 122, 11, 129, 117, 165,
                        181, 92, 98, 167, 33, 90, 48, 149, 171, 253, 67, 70, 142, 166, 163, 47,
                    ],
                ), // this source DOES receive attribution
                /* Third User */
                test_input(
                    345,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    345,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    345,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    345,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    345,
                    false,
                    [
                        107, 205, 128, 36, 178, 207, 60, 220, 201, 97, 152, 28, 38, 53, 186, 254,
                        222, 240, 117, 117, 66, 178, 175, 89, 101, 76, 243, 219, 22, 30, 251, 85,
                    ],
                ), // this source DOES receive attribution
                test_input(
                    345,
                    false,
                    [
                        44, 207, 162, 138, 83, 125, 3, 250, 170, 189, 81, 234, 182, 245, 19, 122,
                        181, 196, 161, 27, 69, 45, 9, 251, 152, 39, 7, 104, 192, 250, 252, 205,
                    ],
                ), // this source does not receive attribution (capped)
                test_input(
                    345,
                    true,
                    [
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0,
                    ],
                ), // trigger
                test_input(
                    345,
                    false,
                    [
                        160, 183, 201, 55, 144, 46, 252, 73, 99, 143, 14, 49, 168, 156, 133, 20,
                        171, 211, 253, 215, 172, 20, 99, 53, 218, 135, 246, 162, 101, 54, 198, 187,
                    ],
                ), // this source does not receive attribution (capped)
            ];

            let expected: [u128; 32] = [
                //      2	8	127	4	19	33	51	92	126	22	60	12	15	201	227	56	107	40	66	29	14	42	78	99	100	48	3	5	9	91	42	198
                //      227	107	125	75	50	15	115	120	49	144	160	122	11	129	117	165	181	92	98	167	33	90	48	149	171	253	67	70	142	166	163	47
                // +    107	205	128	36	178	207	60	220	201	97	152	28	38	53	186	254	222	240	117	117	66	178	175	89	101	76	243	219	22	30	251	85
                // ------------------------------------------------------------------------------------------------------------------------------------
                //      336	320	380	115	247	255	226	432	376	263	372	162	64	383	530	475	510	372	281	313	113	310	301	337	372	377	313	294	173	287	456	330
                336, 320, 380, 115, 247, 255, 226, 432, 376, 263, 372, 162, 64, 383, 530, 475, 510,
                372, 281, 313, 113, 310, 301, 337, 372, 377, 313, 294, 173, 287, 456, 330,
            ];

            let histogram = vec![3, 3, 2, 2, 1, 1, 1, 1];

            let results = world
                .semi_honest(records.into_iter(), |ctx, input_rows| {
                    let h = histogram.as_slice();
                    async move {
                        compute_feature_label_dot_product::<_, U32>(ctx, input_rows, h)
                            .await
                            .unwrap()
                    }
                })
                .await;

            let result = [&results[0], &results[1], &results[2]]
                .reconstruct()
                .iter()
                .map(|x| x.as_u128())
                .collect::<Vec<_>>();

            assert_eq!(&result, &expected);
        });
    }
}
