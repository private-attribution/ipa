use futures::{stream::iter as stream_iter, TryStreamExt};
use futures_util::{future::try_join, StreamExt};
use ipa_macros::Step;

use stream_flatten_iters::StreamExt as _;

use crate::{
    error::Error,
    ff::{Field, GaloisField, Gf2, PrimeField, Serializable},
    protocol::{
        basics::{SecureMul, ShareKnownValue},
        boolean::or::or,
        context::{Context, UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::convert_bits,
        step::BitOpStep,
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        BitDecomposed, Linear as LinearSecretSharing,
    },
    seq_join::seq_join,
};

pub struct PrfShardedIpaInputRow<FV: GaloisField> {
    prf_of_match_key: u64,
    is_trigger_bit: Replicated<Gf2>,
    feature_vector: Replicated<FV>,
}

struct InputsRequiredFromPrevRow {
    ever_encountered_a_trigger_event: Replicated<Gf2>,
    is_saturated: Replicated<Gf2>,
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
    pub async fn compute_row_with_previous<C, FV>(
        &mut self,
        ctx: C,
        record_id: RecordId,
        input_row: &PrfShardedIpaInputRow<FV>,
    ) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
    where
        C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
        FV: GaloisField,
    {
        let share_of_one = Replicated::share_known_value(&ctx, Gf2::ONE);
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

        let unbitpacked_feature_vector = BitDecomposed::decompose(FV::BITS, |i| {
            input_row.feature_vector.map(|v| Gf2::truncate_from(v[i]))
        });

        let capped_attributed_feature_vector = compute_capped_feature_vector(
            ctx.narrow(&Step::ComputedCappedFeatureVector),
            record_id,
            &capped_label,
            &unbitpacked_feature_vector,
        )
        .await?;

        self.ever_encountered_a_trigger_event = ever_encountered_a_trigger_event;
        self.is_saturated = updated_is_saturated;

        Ok(capped_attributed_feature_vector)
    }
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
    PrimeFieldValidator,
    EverEncounteredTriggerEvent,
    DidSourceReceiveAttribution,
    ComputeSaturatingSum,
    IsAttributedSourceAndPrevRowNotSaturated,
    ComputedCappedFeatureVector,
    ModulusConvertFeatureVectorBits,
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

fn chunk_rows_by_user<FV>(
    input_rows: Vec<PrfShardedIpaInputRow<FV>>,
) -> Vec<Vec<PrfShardedIpaInputRow<FV>>>
where
    FV: GaloisField,
{
    let mut rows_for_user: Vec<PrfShardedIpaInputRow<FV>> = vec![];

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
pub async fn compute_feature_label_dot_product<C, FV, F, S>(
    sh_ctx: C,
    input_rows: Vec<PrfShardedIpaInputRow<FV>>,
) -> Result<Vec<S>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F> + Serializable + SecureMul<C::UpgradedContext<F>>,
    FV: GaloisField,
    F: PrimeField + ExtendableField,
{
    assert!(FV::BITS > 0);

    let mut num_outputs = input_rows.len();
    let rows_chunked_by_user = chunk_rows_by_user(input_rows);
    num_outputs -= rows_chunked_by_user.len();
    let histogram = compute_histogram_of_users_with_row_count(&rows_chunked_by_user);
    let binary_validator = sh_ctx.narrow(&Step::BinaryValidator).validator::<Gf2>();
    let binary_m_ctx = binary_validator.context();
    let mut num_users_who_encountered_row_depth = vec![0_u32; histogram.len()];
    let ctx_for_row_number = set_up_contexts(&binary_m_ctx, &histogram);
    let mut futures = Vec::with_capacity(rows_chunked_by_user.len());
    for rows_for_user in rows_chunked_by_user {
        let num_user_rows = rows_for_user.len();
        futures.push(evaluate_per_user_attribution_circuit(
            &ctx_for_row_number,
            num_users_who_encountered_row_depth
                .iter()
                .take(num_user_rows)
                .map(|x| RecordId(*x))
                .collect(),
            rows_for_user,
        ));
        for i in 0..num_user_rows {
            num_users_who_encountered_row_depth[i] += 1;
        }
    }

    let flattenned_stream = seq_join(sh_ctx.active_work(), stream_iter(futures))
        .map(|x| x.unwrap().into_iter())
        .flatten_iters();

    let prime_field_validator = sh_ctx.narrow(&Step::PrimeFieldValidator).validator::<F>();
    let prime_field_ctx = prime_field_validator.context();

    // modulus convert feature vector bits
    let converted_feature_vector_bits = convert_bits(
        prime_field_ctx
            .narrow(&Step::ModulusConvertFeatureVectorBits)
            .set_total_records(num_outputs),
        flattenned_stream,
        0..FV::BITS,
    );

    converted_feature_vector_bits
        .try_fold(
            vec![S::ZERO; usize::try_from(FV::BITS).unwrap()],
            |mut running_sums, row_contribution| async move {
                for (i, contribution) in row_contribution.iter().enumerate() {
                    running_sums[i] += contribution;
                }
                Ok(running_sums)
            },
        )
        .await
}

async fn evaluate_per_user_attribution_circuit<C, FV>(
    ctx_for_row_number: &[C],
    record_id_for_each_depth: Vec<RecordId>,
    rows_for_user: Vec<PrfShardedIpaInputRow<FV>>,
) -> Result<Vec<BitDecomposed<Replicated<Gf2>>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
    FV: GaloisField,
{
    assert!(!rows_for_user.is_empty());
    if rows_for_user.len() == 1 {
        return Ok(Vec::new());
    }
    let first_row = &rows_for_user[0];
    let mut prev_row_inputs = initialize_new_device_attribution_variables(first_row);

    let mut output = Vec::with_capacity(rows_for_user.len() - 1);
    for (i, row) in rows_for_user.iter().skip(1).enumerate() {
        let ctx_for_this_row_depth = ctx_for_row_number[i].clone(); // no context was created for row 0
        let record_id_for_this_row_depth = record_id_for_each_depth[i + 1]; // skip row 0

        let capped_attribution_outputs = prev_row_inputs
            .compute_row_with_previous(ctx_for_this_row_depth, record_id_for_this_row_depth, row)
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
    FV: GaloisField,
{
    InputsRequiredFromPrevRow {
        ever_encountered_a_trigger_event: input_row.is_trigger_bit.clone(),
        is_saturated: Replicated::ZERO,
    }
}

async fn compute_capped_feature_vector<C>(
    ctx: C,
    record_id: RecordId,
    capped_label: &Replicated<Gf2>,
    feature_vector: &BitDecomposed<Replicated<Gf2>>,
) -> Result<BitDecomposed<Replicated<Gf2>>, Error>
where
    C: UpgradedContext<Gf2, Share = Replicated<Gf2>>,
{
    Ok(BitDecomposed::new(
        ctx.parallel_join(feature_vector.iter().enumerate().map(|(i, bit)| {
            let c1 = ctx.narrow(&BitOpStep::from(i));
            async move { capped_label.multiply(bit, c1, record_id).await }
        }))
        .await?,
    ))
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use crate::{
        ff::{Field, Fp32BitPrime, GaloisField, Gf2, Gf32Bit},
        protocol::prf_sharding::feature_label_dot_product::{
            compute_feature_label_dot_product, PrfShardedIpaInputRow,
        },
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, IntoShares, SharedValue,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    struct PreShardedAndSortedOPRFTestInput<FV: GaloisField> {
        prf_of_match_key: u64,
        is_trigger_bit: Gf2,
        feature_vector: FV,
    }

    fn test_input(
        prf_of_match_key: u64,
        is_trigger: bool,
        feature_vector: u32,
    ) -> PreShardedAndSortedOPRFTestInput<Gf32Bit> {
        let is_trigger_bit = if is_trigger { Gf2::ONE } else { Gf2::ZERO };

        PreShardedAndSortedOPRFTestInput {
            prf_of_match_key,
            is_trigger_bit,
            feature_vector: Gf32Bit::truncate_from(feature_vector),
        }
    }

    impl<FV> IntoShares<PrfShardedIpaInputRow<FV>> for PreShardedAndSortedOPRFTestInput<FV>
    where
        FV: GaloisField + IntoShares<Replicated<FV>>,
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

            let records: Vec<PreShardedAndSortedOPRFTestInput<Gf32Bit>> = vec![
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

            let result: Vec<_> = world
                .semi_honest(records.into_iter(), |ctx, input_rows| async move {
                    compute_feature_label_dot_product::<
                        _,
                        Gf32Bit,
                        Fp32BitPrime,
                        Replicated<Fp32BitPrime>,
                    >(ctx, input_rows)
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            assert_eq!(result, &expected);
        });
    }
}
