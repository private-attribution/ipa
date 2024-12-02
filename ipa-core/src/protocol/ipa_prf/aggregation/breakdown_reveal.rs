use std::{convert::Infallible, pin::pin};

use futures::stream;
use futures_util::{StreamExt, TryStreamExt};
use tracing::{info_span, Instrument};

use super::aggregate_values;
use crate::{
    error::{Error, UnwrapInfallible},
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BooleanArrayReader, BooleanArrayWriter, BA32},
        U128Conversions,
    },
    helpers::TotalRecords,
    protocol::{
        basics::{reveal, Reveal},
        context::{
            dzkp_validator::DZKPValidator, Context, DZKPUpgraded, MaliciousProtocolSteps,
            UpgradableContext,
        },
        ipa_prf::{
            aggregation::{
                aggregate_values_proof_chunk, step::AggregationStep as Step, AGGREGATE_DEPTH,
            },
            oprf_padding::{apply_dp_padding, PaddingParameters},
            prf_sharding::{AttributionOutputs, SecretSharedAttributionOutputs},
            shuffle::{Shuffle, Shuffleable},
            BreakdownKey,
        },
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing},
        BitDecomposed, FieldSimd, SharedValue, TransposeFrom, Vectorizable,
    },
    seq_join::seq_join,
};

impl<BK, TV> AttributionOutputs<Replicated<BK>, Replicated<TV>>
where
    BK: BooleanArray,
    TV: BooleanArray,
{
    fn join_fields(breakdown_key: BK, trigger_value: TV) -> <Self as Shuffleable>::Share {
        let mut share = <Self as Shuffleable>::Share::ZERO;

        BooleanArrayWriter::new(&mut share)
            .write(&breakdown_key)
            .write(&trigger_value);

        share
    }

    fn split_fields(share: &<Self as Shuffleable>::Share) -> (BK, TV) {
        let bits = BooleanArrayReader::new(share);
        let (breakdown_key, bits) = bits.read();
        let (trigger_value, _bits) = bits.read();
        (breakdown_key, trigger_value)
    }
}

impl<BK, TV> Shuffleable for AttributionOutputs<Replicated<BK>, Replicated<TV>>
where
    BK: BooleanArray,
    TV: BooleanArray,
{
    /// TODO: Use a smaller BA type to contain BK and TV
    type Share = BA32;

    fn left(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::left(&self.attributed_breakdown_key_bits),
            ReplicatedSecretSharing::left(&self.capped_attributed_trigger_value),
        )
    }

    fn right(&self) -> Self::Share {
        Self::join_fields(
            ReplicatedSecretSharing::right(&self.attributed_breakdown_key_bits),
            ReplicatedSecretSharing::right(&self.capped_attributed_trigger_value),
        )
    }

    fn new(l: Self::Share, r: Self::Share) -> Self {
        debug_assert!(
            BK::BITS + TV::BITS <= Self::Share::BITS,
            "share type {} is too small",
            std::any::type_name::<Self::Share>(),
        );

        let left = Self::split_fields(&l);
        let right = Self::split_fields(&r);

        Self {
            attributed_breakdown_key_bits: ReplicatedSecretSharing::new(left.0, right.0),
            capped_attributed_trigger_value: ReplicatedSecretSharing::new(left.1, right.1),
        }
    }
}

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
pub async fn breakdown_reveal_aggregation<C, BK, TV, HV, const B: usize>(
    ctx: C,
    attributed_values: Vec<SecretSharedAttributionOutputs<BK, TV>>,
    padding_params: &PaddingParameters,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    C: UpgradableContext + Shuffle,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<DZKPUpgraded<C>, B>,
    BK: BreakdownKey<B>,
    Replicated<BK>: Reveal<DZKPUpgraded<C>, Output = <BK as Vectorizable<1>>::Array>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
{
    // Apply DP padding for Breakdown Reveal Aggregation
    let attributed_values_padded =
        apply_dp_padding::<_, AttributionOutputs<Replicated<BK>, Replicated<TV>>, B>(
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
    let mut depth = 0;
    let agg_proof_chunk = aggregate_values_proof_chunk(B, usize::try_from(TV::BITS).unwrap());

    while intermediate_results.len() > 1 {
        let mut record_ids = [RecordId::FIRST; AGGREGATE_DEPTH];
        let mut next_intermediate_results = Vec::new();
        for (chunk_counter, chunk) in intermediate_results.chunks(agg_proof_chunk).enumerate() {
            let chunk_len = chunk.len();
            let validator = ctx.clone().dzkp_validator(
                MaliciousProtocolSteps {
                    protocol: &Step::aggregate(depth),
                    validate: &Step::aggregate_validate(depth),
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
            next_intermediate_results.push(result);
        }
        depth += 1;
        intermediate_results = next_intermediate_results;
    }

    let mut result = intermediate_results
        .into_iter()
        .next()
        .expect("aggregation input must not be empty");

    // If there were less than 2^(|ov| - |tv|) inputs, then we didn't add enough carries to produce
    // a full-length output, so pad the output now.
    result.resize(
        usize::try_from(HV::BITS).unwrap(),
        Replicated::<Boolean, B>::ZERO,
    );

    Ok(result)
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
    Replicated<BK>: Reveal<C, Output = <BK as Vectorizable<1>>::Array>,
    TV: BooleanArray + U128Conversions,
{
    let reveal_ctx = parent_ctx.set_total_records(TotalRecords::specified(attributions.len())?);

    let reveal_work = stream::iter(attributions).enumerate().map(|(i, ao)| {
        let record_id = RecordId::from(i);
        let reveal_ctx = reveal_ctx.clone();
        async move {
            let revealed_bk =
                reveal(reveal_ctx, record_id, &ao.attributed_breakdown_key_bits).await?;
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
}

impl<TV: BooleanArray, const B: usize> From<GroupedTriggerValues<TV, B>>
    for Vec<BitDecomposed<Replicated<Boolean, B>>>
where
    Boolean: FieldSimd<B>,
    BitDecomposed<Replicated<Boolean, B>>:
        for<'a> TransposeFrom<&'a [Replicated<TV>; B], Error = Infallible>,
{
    fn from(
        mut grouped_tvs: GroupedTriggerValues<TV, B>,
    ) -> Vec<BitDecomposed<Replicated<Boolean, B>>> {
        let iter = (0..grouped_tvs.max_len).map(move |_| {
            let slice: [Replicated<TV>; B] = grouped_tvs
                .tvs
                .each_mut()
                .map(|tv| tv.pop().unwrap_or(Replicated::ZERO));

            BitDecomposed::transposed_from(&slice).unwrap_infallible()
        });
        iter.collect()
    }
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use std::cmp::min;

    use futures::TryFutureExt;
    use proptest::{prelude::*, prop_compose};
    use rand::seq::SliceRandom;

    use crate::{
        const_assert,
        ff::{
            boolean::Boolean,
            boolean_array::{BA3, BA32, BA5, BA8},
            U128Conversions,
        },
        protocol::ipa_prf::{
            aggregation::breakdown_reveal::breakdown_reveal_aggregation,
            oprf_padding::PaddingParameters,
            prf_sharding::{
                AttributionOutputs, AttributionOutputsTestInput, SecretSharedAttributionOutputs,
            },
        },
        rand::Rng,
        secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, IntoShares,
            SharedValue, TransposeFrom,
        },
        test_executor::run_with,
        test_fixture::{
            mpc_proptest_config_with_cases, Reconstruct, ReconstructArr, Runner, TestWorld,
        },
    };
    #[cfg(not(feature = "shuttle"))]
    use crate::{ff::boolean_array::BA16, test_executor::run};

    fn input_row(bk: usize, tv: u128) -> AttributionOutputsTestInput<BA5, BA3> {
        let bk: u128 = bk.try_into().unwrap();
        AttributionOutputsTestInput {
            bk: BA5::truncate_from(bk),
            tv: BA3::truncate_from(tv),
        }
    }

    #[test]
    fn semi_honest_happy_path() {
        // if shuttle executor is enabled, run this test only once.
        // it is a very expensive test to explore all possible states,
        // sometimes github bails after 40 minutes of running it
        // (workers there are really slow).
        run_with::<_, _, 3>(|| async {
            let world = TestWorld::default();
            let mut rng = world.rng();
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
                .semi_honest(inputs.into_iter(), |ctx, input_rows| async move {
                    let aos = input_rows
                        .into_iter()
                        .map(|ti| SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                        .collect();
                    let r: Vec<Replicated<BA8>> =
                        breakdown_reveal_aggregation::<_, BA5, BA3, BA8, 32>(
                            ctx,
                            aos,
                            &PaddingParameters::relaxed(),
                        )
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

    #[test]
    #[cfg(not(feature = "shuttle"))] // too slow
    fn malicious_happy_path() {
        use crate::{sharding::NotSharded, test_fixture::TestWorldConfig};

        type HV = BA16;
        run(|| async {
            let config = TestWorldConfig::default().with_timeout_secs(60);
            let world = TestWorld::<NotSharded>::with_config(&config);
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
                .malicious(inputs.into_iter(), |ctx, input_rows| async move {
                    let aos = input_rows
                        .into_iter()
                        .map(|ti| SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                        .collect();
                    breakdown_reveal_aggregation::<_, BA5, BA3, HV, 32>(
                        ctx,
                        aos,
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

    type PropBreakdownKey = BA5;
    type PropTriggerValue = BA3;
    type PropHistogramValue = BA8;
    type PropBucketsBitVec = BA32;
    const PROP_MAX_INPUT_LEN: usize = 2500;
    const PROP_BUCKETS: usize = PropBucketsBitVec::BITS as usize;

    // We want to capture everything in this struct for visibility in the output of failing runs,
    // even if it isn't used by the test.
    #[allow(dead_code)]
    #[derive(Debug)]
    struct AggregatePropTestInputs {
        inputs: Vec<AttributionOutputs<usize, u32>>,
        expected: BitDecomposed<PropBucketsBitVec>,
        len: usize,
    }

    const_assert!(
        PropHistogramValue::BITS < u32::BITS,
        "(1 << PropHistogramValue::BITS) must fit in u32",
    );

    const_assert!(
        PROP_BUCKETS <= 1 << PropBreakdownKey::BITS,
        "PROP_BUCKETS must fit in PropBreakdownKey",
    );

    impl<BK, TV> From<(BK, TV)> for AttributionOutputs<BK, TV> {
        fn from(value: (BK, TV)) -> Self {
            AttributionOutputs {
                attributed_breakdown_key_bits: value.0,
                capped_attributed_trigger_value: value.1,
            }
        }
    }

    impl IntoShares<SecretSharedAttributionOutputs<PropBreakdownKey, PropTriggerValue>>
        for AttributionOutputs<usize, u32>
    {
        fn share_with<R: Rng>(
            self,
            rng: &mut R,
        ) -> [SecretSharedAttributionOutputs<PropBreakdownKey, PropTriggerValue>; 3] {
            let [bk_0, bk_1, bk_2] = PropBreakdownKey::truncate_from(
                u128::try_from(self.attributed_breakdown_key_bits).unwrap(),
            )
            .share_with(rng);
            let [tv_0, tv_1, tv_2] =
                PropTriggerValue::truncate_from(u128::from(self.capped_attributed_trigger_value))
                    .share_with(rng);
            [(bk_0, tv_0), (bk_1, tv_1), (bk_2, tv_2)].map(Into::into)
        }
    }

    prop_compose! {
        fn inputs(max_len: usize)
                 (
                     len in 1..=max_len,
                 )
                 (
                     len in Just(len),
                     inputs in prop::collection::vec((0..PROP_BUCKETS, 0u32..1 << PropTriggerValue::BITS).prop_map(Into::into), len),
                 )
        -> AggregatePropTestInputs {
            let mut expected = [0; PROP_BUCKETS];
            for input in &inputs {
                let AttributionOutputs {
                    attributed_breakdown_key_bits: bk,
                    capped_attributed_trigger_value: tv,
                } = *input;
                expected[bk] = min(expected[bk] + tv, (1 << PropHistogramValue::BITS) - 1);
            }

            let expected = BitDecomposed::decompose(PropHistogramValue::BITS, |i| {
                expected.iter().map(|v| Boolean::from((v >> i) & 1 == 1)).collect()
            });

            AggregatePropTestInputs {
                inputs,
                expected,
                len,
            }
        }
    }

    proptest! {
        #![proptest_config(mpc_proptest_config_with_cases(100))]
        #[test]
        fn breakdown_reveal_proptest(
            input_struct in inputs(PROP_MAX_INPUT_LEN),
            seed in any::<u64>(),
        ) {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let AggregatePropTestInputs {
                    inputs,
                    expected,
                    ..
                } = input_struct;
                let result = TestWorld::with_seed(seed)
                    .malicious(inputs.into_iter(), |ctx, inputs| async move {
                        breakdown_reveal_aggregation::<_, _, _, PropHistogramValue, {PropBucketsBitVec::BITS as usize}>(
                            ctx,
                            inputs,
                            &PaddingParameters::no_padding(),
                        ).await
                    })
                    .await
                    .map(Result::unwrap)
                    .reconstruct_arr();

                assert_eq!(result, expected);
            });
        }
    }
}
