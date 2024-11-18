use std::{convert::Infallible, pin::pin};

use futures::stream;
use futures_util::{StreamExt, TryStreamExt};
use tracing::{info_span, Instrument};

use crate::{
    error::{Error, UnwrapInfallible},
    ff::{boolean::Boolean, boolean_array::BooleanArray, U128Conversions},
    helpers::TotalRecords,
    protocol::{
        basics::{reveal, Reveal},
        context::{
            dzkp_validator::DZKPValidator, Context, DZKPUpgraded, MaliciousProtocolSteps,
            UpgradableContext,
        },
        ipa_prf::{
            aggregation::{
                aggregate_values, aggregate_values_proof_chunk, step::AggregationStep as Step,
                AGGREGATE_DEPTH,
            },
            oprf_padding::{apply_dp_padding, PaddingParameters},
            shuffle::Shuffle,
        },
        BooleanProtocols, RecordId,
    },
    report::hybrid::AggregateableHybridReport,
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        TransposeFrom, Vectorizable,
    },
    seq_join::seq_join,
};

/// Improved Aggregation a.k.a Aggregation revealing breakdown.
///
/// Aggregation steps happen after attribution. the input for Aggregation is a
/// list of tuples containing Trigger Values (TV) and their corresponding
/// Breakdown Keys (BK), which were attributed in the previous step of IPA. The
/// output of Aggregation is a histogram, where each “bin” or "bucket" is a BK
/// and the value is the addition of all the TVs for it, hence the name
/// Aggregation. This can be thought as a SQL GROUP BY operation.
///
/// The protocol involves four main steps:
/// 1. Shuffle the data to protect privacy (see [`shuffle_attributions`]).
/// 2. Reveal breakdown keys. This is the key difference to the previous
///    aggregation (see [`reveal_breakdowns`]).
/// 3. Add all values for each breakdown.
///
/// This protocol explicitly manages proof batches for DZKP-based malicious security by
/// processing chunks of values from `intermediate_results.chunks()`. Procession
/// through record IDs is not uniform for all of the gates in the protocol. The first
/// layer of the reduction adds N pairs of records, the second layer adds N/2 pairs of
/// records, etc. This has a few consequences:
///   * We must specify a batch size of `usize::MAX` when calling `dzkp_validator`.
///   * We must track record IDs across chunks, so that subsequent chunks can
///     start from the last record ID that was used in the previous chunk.
///   * Because the first record ID in the proof batch is set implicitly, we must
///     guarantee that it submits multiplication intermediates before any other
///     record. This is currently ensured by the serial operation of the aggregation
///     protocol (i.e. by not using `seq_join`).
#[tracing::instrument(name = "breakdown_reveal_aggregation", skip_all, fields(total = attributed_values.len()))]
pub async fn breakdown_reveal_aggregation<C, BK, V, HV, const B: usize>(
    ctx: C,
    attributed_values: Vec<AggregateableHybridReport<BK, V>>,
    padding_params: &PaddingParameters,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: UpgradableContext + Shuffle,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    BK: BooleanArray + U128Conversions,
    Replicated<BK>: Reveal<DZKPUpgraded<C>, Output = <BK as Vectorizable<1>>::Array>,
    V: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<V>; B], Error = Infallible>,
{
    // Apply DP padding for Breakdown Reveal Aggregation
    let attributed_values_padded = apply_dp_padding::<_, AggregateableHybridReport<BK, V>, B>(
        ctx.narrow(&Step::PaddingDp),
        attributed_values,
        padding_params,
    )
    .await?;

    let attributions = ctx
        .narrow(&Step::Shuffle)
        .shuffle(attributed_values_padded)
        .instrument(info_span!("shuffle_attribution_outputs"))
        .await?;

    // Revealing the breakdowns doesn't do any multiplies, so won't make it as far as
    // doing a proof, but we need the validator to obtain an upgraded malicious context.
    let validator = ctx.clone().dzkp_validator(
        MaliciousProtocolSteps {
            protocol: &Step::Reveal,
            validate: &Step::RevealValidate,
        },
        usize::MAX,
    );
    let grouped_tvs = reveal_breakdowns(&validator.context(), attributions).await?;
    validator.validate().await?;
    let mut intermediate_results: Vec<BitDecomposed<Replicated<Boolean, B>>> = grouped_tvs.into();

    // Any real-world aggregation should be able to complete in two layers (two
    // iterations of the `while` loop below). Tests with small `TARGET_PROOF_SIZE`
    // may exceed that.
    let mut chunk_counter = 0;
    let mut depth = 0;
    let agg_proof_chunk = aggregate_values_proof_chunk(B, usize::try_from(V::BITS).unwrap());

    while intermediate_results.len() > 1 {
        let mut record_ids = [RecordId::FIRST; AGGREGATE_DEPTH];
        let mut next_intermediate_results = Vec::new();
        for chunk in intermediate_results.chunks(agg_proof_chunk) {
            let chunk_len = chunk.len();
            let validator = ctx.clone().dzkp_validator(
                MaliciousProtocolSteps {
                    protocol: &Step::aggregate(depth),
                    validate: &Step::AggregateValidate,
                },
                usize::MAX, // See note about batching above.
            );
            let result = aggregate_values::<_, HV, B>(
                validator.context(),
                stream::iter(chunk).map(|v| Ok(v.clone())).boxed(),
                chunk_len,
                Some(&mut record_ids),
            )
            .await?;
            validator.validate_indexed(chunk_counter).await?;
            chunk_counter += 1;
            next_intermediate_results.push(result);
        }
        depth += 1;
        intermediate_results = next_intermediate_results;
    }

    Ok(intermediate_results
        .into_iter()
        .next()
        .expect("aggregation input must not be empty"))
}

/// Transforms the Breakdown key from a secret share into a revealed `usize`.
/// The input are the Atrributions and the output is a list of lists of secret
/// shared Trigger Values. Since Breakdown Keys are assumed to be dense the
/// first list contains all the possible Breakdowns, the index in the list
/// representing the Breakdown value. The second list groups all the Trigger
/// Values for that particular Breakdown.
#[tracing::instrument(name = "reveal_breakdowns", skip_all, fields(
    total = attributions.len(),
))]
async fn reveal_breakdowns<C, BK, V, const B: usize>(
    parent_ctx: &C,
    attributions: Vec<AggregateableHybridReport<BK, V>>,
) -> Result<ValueHistogram<V, B>, Error>
where
    C: Context,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    Boolean: FieldSimd<B>,
    BK: BooleanArray + U128Conversions,
    Replicated<BK>: Reveal<C, Output = <BK as Vectorizable<1>>::Array>,
    V: BooleanArray + U128Conversions,
{
    let reveal_ctx = parent_ctx.set_total_records(TotalRecords::specified(attributions.len())?);

    let reveal_work = stream::iter(attributions).enumerate().map(|(i, report)| {
        let record_id = RecordId::from(i);
        let reveal_ctx = reveal_ctx.clone();
        async move {
            let revealed_bk = reveal(reveal_ctx, record_id, &report.breakdown_key).await?;
            let revealed_bk = BK::from_array(&revealed_bk);
            let Ok(bk) = usize::try_from(revealed_bk.as_u128()) else {
                return Err(Error::Internal);
            };
            Ok::<_, Error>((bk, report.value))
        }
    });
    let mut grouped_tvs = ValueHistogram::<V, B>::new();
    let mut stream = pin!(seq_join(reveal_ctx.active_work(), reveal_work));
    while let Some((bk, tv)) = stream.try_next().await? {
        grouped_tvs.push(bk, tv);
    }

    Ok(grouped_tvs)
}

/// Helper type that hold all the Trigger Values, grouped by their Breakdown
/// Key. The main functionality is to turn into a stream that can be given to
/// [`aggregate_values`].
struct ValueHistogram<V: BooleanArray, const B: usize> {
    tvs: [Vec<Replicated<V>>; B],
    max_len: usize,
}

impl<V: BooleanArray, const B: usize> ValueHistogram<V, B> {
    fn new() -> Self {
        Self {
            tvs: std::array::from_fn(|_| vec![]),
            max_len: 0,
        }
    }

    fn push(&mut self, bk: usize, value: Replicated<V>) {
        self.tvs[bk].push(value);
        if self.tvs[bk].len() > self.max_len {
            self.max_len = self.tvs[bk].len();
        }
    }
}

impl<V: BooleanArray, const B: usize> From<ValueHistogram<V, B>>
    for Vec<BitDecomposed<Replicated<Boolean, B>>>
where
    Boolean: FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<V>; B], Error = Infallible>,
{
    fn from(mut grouped_tvs: ValueHistogram<V, B>) -> Vec<BitDecomposed<Replicated<Boolean, B>>> {
        let iter = (0..grouped_tvs.max_len).map(move |_| {
            let slice: [Replicated<V>; B] = grouped_tvs
                .tvs
                .each_mut()
                .map(|tv| tv.pop().unwrap_or(Replicated::ZERO));

            BitDecomposed::transposed_from(&slice).unwrap_infallible()
        });
        iter.collect()
    }
}

#[cfg(all(test, unit_test, not(feature = "shuttle")))]
pub mod tests {
    use futures::TryFutureExt;
    use rand::seq::SliceRandom;

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA16, BA3, BA5},
            U128Conversions,
        },
        protocol::{
            hybrid::breakdown_reveal_aggregation, ipa_prf::oprf_padding::PaddingParameters,
        },
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, TransposeFrom,
        },
        test_executor::run,
        test_fixture::{hybrid::TestAggregateableHybridReport, Reconstruct, Runner, TestWorld},
    };

    fn input_row(breakdown_key: usize, value: u128) -> TestAggregateableHybridReport {
        TestAggregateableHybridReport {
            match_key: (),
            value: value.try_into().unwrap(),
            breakdown_key: breakdown_key.try_into().unwrap(),
        }
    }

    #[test]
    fn breakdown_reveal_malicious_happy_path() {
        type HV = BA16;
        run(|| async {
            let world = TestWorld::default();
            let mut rng = world.rng();
            let mut expectation = Vec::new();
            for _ in 0..32 {
                expectation.push(rng.gen_range(0u128..512));
            }
            // The size of input needed here to get complete coverage (more precisely,
            // the size of input to the final aggregation using `aggregate_values`)
            // depends on `TARGET_PROOF_SIZE`.
            let expectation = expectation; // no more mutability for safety
            let mut inputs = Vec::new();
            // Builds out inputs with values for each breakdown_key that add up to
            // the expectation. Expectation is ranomg (0..512). Each iteration
            // generates a value (0..8) and subtracts from the expectation until a final
            // remaninder in (0..8) remains to be added to the vec.
            for (breakdown_key, expected_value) in expectation.iter().enumerate() {
                let mut remainder = *expected_value;
                while remainder > 7 {
                    let value = rng.gen_range(0u128..8);
                    remainder -= value;
                    inputs.push(input_row(breakdown_key, value));
                }
                inputs.push(input_row(breakdown_key, remainder));
            }
            inputs.shuffle(&mut rng);
            let result: Vec<_> = world
                .malicious(inputs.into_iter(), |ctx, reports| async move {
                    breakdown_reveal_aggregation::<_, BA5, BA3, HV, 32>(
                        ctx,
                        reports,
                        &PaddingParameters::relaxed(),
                    )
                    .map_ok(|d: BitDecomposed<Replicated<Boolean, 32>>| {
                        Vec::transposed_from(&d).unwrap()
                    })
                    .await
                    .unwrap()
                })
                .await
                .reconstruct();
            let result = result.iter().map(|v: &HV| v.as_u128()).collect::<Vec<_>>();
            assert_eq!(32, result.len());
            assert_eq!(result, expectation);
        });
    }
}
