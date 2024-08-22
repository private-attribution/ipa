use std::{
    convert::Infallible,
    pin::{pin, Pin},
};

use futures::{stream, Stream};
use futures_util::{StreamExt, TryStreamExt};

use super::{aggregate_values, AggResult};
use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA64},
        U128Conversions,
    },
    helpers::TotalRecords,
    protocol::{
        basics::semi_honest_reveal,
        context::Context,
        ipa_prf::{
            aggregation::step::AggregationStep,
            oprf_padding::{apply_dp_padding, PaddingParameters},
            prf_sharding::{AttributionOutputs, SecretSharedAttributionOutputs},
            shuffle::shuffle_attribution_outputs,
            BreakdownKey, OPRFIPAInputRow,
        },
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        TransposeFrom,
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
pub async fn breakdown_reveal_aggregation<C, BK, TV, HV, const B: usize>(
    ctx: C,
    attributed_values: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: Context,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
{
    let dp_padding_params = PaddingParameters::relaxed();
    // Apply DP padding for Breakdown Reveal Aggregation
    let attributed_values_padded =
        apply_dp_padding::<_, AttributionOutputs<Replicated<BK>, Replicated<TV>>, B>(
            ctx.narrow(&AggregationStep::PaddingDp),
            attributed_values,
            dp_padding_params,
        )
        .await?;

    let atributions = shuffle_attributions(&ctx, attributed_values_padded).await?;
    let grouped_tvs = reveal_breakdowns(&ctx, atributions).await?;
    let num_rows = grouped_tvs.max_len;
    aggregate_values::<_, HV, B>(ctx, grouped_tvs.into_stream(), num_rows).await
}

/// Shuffles attribution Breakdown key and Trigger Value secret shares. Input
/// and output are the same type.
///
/// TODO: Use a smaller BA type to contain BK and TV
/// TODO: Sharded shuffle
async fn shuffle_attributions<C, BK, TV, const B: usize>(
    parent_ctx: &C,
    contribs: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<SecretSharedAttributionOutputs<BK, TV>>, Error>
where
    C: Context,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
{
    let shuffle_ctx = parent_ctx.narrow(&AggregationStep::Shuffle);
    shuffle_attribution_outputs::<_, BK, TV, BA64>(shuffle_ctx, contribs).await
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
async fn reveal_breakdowns<C, BK, TV, const B: usize>(
    parent_ctx: &C,
    attributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<GroupedTriggerValues<TV, B>, Error>
where
    C: Context,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
    Boolean: FieldSimd<B>,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
{
    let reveal_ctx = parent_ctx
        .narrow(&AggregationStep::RevealStep)
        .set_total_records(TotalRecords::specified(attributions.len())?);

    let reveal_work = stream::iter(attributions).enumerate().map(|(i, ao)| {
        let record_id = RecordId::from(i);
        let reveal_ctx = reveal_ctx.clone();
        async move {
            let revealed_bk = semi_honest_reveal(
                reveal_ctx,
                record_id,
                None,
                &ao.attributed_breakdown_key_bits,
            )
            .await?
            // Full reveal is used, meaning it is not possible to return None here
            .unwrap();
            let revealed_bk = BK::from_array(&revealed_bk);
            let Ok(bk) = usize::try_from(revealed_bk.as_u128()) else {
                return Err(Error::Internal);
            };
            Ok::<_, Error>((bk, ao.capped_attributed_trigger_value))
        }
    });
    let mut grouped_tvs = GroupedTriggerValues::<TV, B>::new();
    let mut stream = pin!(seq_join(reveal_ctx.active_work(), reveal_work));
    while let Some((bk, tv)) = stream.try_next().await? {
        grouped_tvs.push(bk, tv);
    }

    Ok(grouped_tvs)
}

/// Helper type that hold all the Trigger Values, grouped by their Breakdown
/// Key. The main functionality is to turn into a stream that can be given to
/// [`aggregate_values`].
struct GroupedTriggerValues<TV: BooleanArray, const B: usize> {
    tvs: [Vec<Replicated<TV>>; B],
    max_len: usize,
}

impl<TV: BooleanArray, const B: usize> GroupedTriggerValues<TV, B> {
    fn new() -> Self {
        Self {
            tvs: std::array::from_fn(|_| vec![]),
            max_len: 0,
        }
    }

    fn push(&mut self, bk: usize, value: Replicated<TV>) {
        self.tvs[bk].push(value);
        if self.tvs[bk].len() > self.max_len {
            self.max_len = self.tvs[bk].len();
        }
    }

    fn into_stream<'fut>(mut self) -> Pin<Box<dyn Stream<Item = AggResult<B>> + Send + 'fut>>
    where
        Boolean: FieldSimd<B>,
        BitDecomposed<Replicated<Boolean, B>>:
            for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
    {
        let iter = (0..self.max_len).map(move |_| {
            let slice: [Replicated<TV>; B] = self
                .tvs
                .each_mut()
                .map(|tv| tv.pop().unwrap_or(Replicated::ZERO));

            Ok(BitDecomposed::transposed_from(&slice).unwrap_infallible())
        });
        Box::pin(stream::iter(iter))
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use futures::TryFutureExt;
    use rand::{seq::SliceRandom, Rng};

    use crate::{
        ff::{
            boolean::Boolean,
            boolean_array::{BA3, BA5, BA8},
            U128Conversions,
        },
        protocol::ipa_prf::{
            aggregation::breakdown_reveal::breakdown_reveal_aggregation,
            prf_sharding::{AttributionOutputsTestInput, SecretSharedAttributionOutputs},
        },
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, TransposeFrom,
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn input_row(bk: usize, tv: u128) -> AttributionOutputsTestInput<BA5, BA3> {
        let bk: u128 = bk.try_into().unwrap();
        AttributionOutputsTestInput {
            bk: BA5::truncate_from(bk),
            tv: BA3::truncate_from(tv),
        }
    }

    #[test]
    fn semi_honest_happy_path() {
        run(|| async {
            let world = TestWorld::default();
            let mut rng = rand::thread_rng();
            let mut expectation = Vec::new();
            for _ in 0..32 {
                expectation.push(rng.gen_range(0u128..256));
            }
            let expectation = expectation; // no more mutability for safety
            let mut inputs = Vec::new();
            for (bk, expected_hv) in expectation.iter().enumerate() {
                let mut remainder = *expected_hv;
                while remainder > 7 {
                    let tv = rng.gen_range(0u128..8);
                    remainder -= tv;
                    inputs.push(input_row(bk, tv));
                }
                inputs.push(input_row(bk, remainder));
            }
            inputs.shuffle(&mut rng);
            let result: Vec<_> = world
                .upgraded_semi_honest(inputs.into_iter(), |ctx, input_rows| async move {
                    let aos = input_rows
                        .into_iter()
                        .map(|ti| SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                        .collect();
                    let r: Vec<Replicated<BA8>> =
                        breakdown_reveal_aggregation::<_, BA5, BA3, BA8, 32>(ctx, aos)
                            .map_ok(|d: BitDecomposed<Replicated<Boolean, 32>>| {
                                Vec::transposed_from(&d).unwrap()
                            })
                            .await
                            .unwrap();
                    r
                })
                .await
                .reconstruct();
            let result = result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>();
            assert_eq!(32, result.len());
            assert_eq!(result, expectation);
        });
    }
}
