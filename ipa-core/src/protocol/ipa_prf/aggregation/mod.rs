use std::{any::type_name, cmp::max, iter, pin::Pin};

use futures::{Stream, StreamExt, TryStreamExt};
use tracing::Instrument;

use crate::{
    error::{Error, LengthError},
    ff::{boolean::Boolean, boolean_array::BooleanArray, U128Conversions},
    helpers::{
        stream::{ChunkBuffer, FixedLength},
        TotalRecords,
    },
    protocol::{
        basics::BooleanProtocols,
        boolean::{step::ThirtyTwoBitStep, NBitStep},
        context::{dzkp_validator::TARGET_PROOF_SIZE, Context},
        ipa_prf::{
            aggregation::step::{AggregateChunkStep, AggregateValuesStep},
            boolean_ops::addition_sequential::{integer_add, integer_sat_add},
            prf_sharding::AttributionOutputs,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        SharedValue, TransposeFrom, Vectorizable,
    },
};

pub(crate) mod breakdown_reveal;
pub(crate) mod step;

type AttributionOutputsChunk<const N: usize> = AttributionOutputs<
    BitDecomposed<Replicated<Boolean, N>>,
    BitDecomposed<Replicated<Boolean, N>>,
>;

impl<BK, TV, const N: usize> ChunkBuffer<N>
    for AttributionOutputs<Vec<Replicated<BK>>, Vec<Replicated<TV>>>
where
    Boolean: Vectorizable<N>,
    BK: SharedValue,
    TV: SharedValue,
    BitDecomposed<Replicated<Boolean, N>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, N>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<TV>>, Error = LengthError>,
{
    type Item = AttributionOutputs<Replicated<BK>, Replicated<TV>>;
    type Chunk = AttributionOutputsChunk<N>;

    fn push(&mut self, item: Self::Item) {
        self.attributed_breakdown_key_bits
            .push(item.attributed_breakdown_key_bits);
        self.capped_attributed_trigger_value
            .push(item.capped_attributed_trigger_value);
    }

    fn len(&self) -> usize {
        assert_eq!(
            self.attributed_breakdown_key_bits.len(),
            self.capped_attributed_trigger_value.len()
        );
        self.attributed_breakdown_key_bits.len()
    }

    fn resize_with<F: Fn() -> Self::Item>(&mut self, len: usize, f: F) {
        while self.attributed_breakdown_key_bits.len() < len {
            <Self as ChunkBuffer<N>>::push(self, f());
        }
    }

    fn take(&mut self) -> Result<Self::Chunk, LengthError> {
        // Aggregation input transpose
        let bk = BitDecomposed::transposed_from(&self.attributed_breakdown_key_bits)?;
        let tv = BitDecomposed::transposed_from(&self.capped_attributed_trigger_value)?;
        self.attributed_breakdown_key_bits = Vec::with_capacity(N);
        self.capped_attributed_trigger_value = Vec::with_capacity(N);
        Ok(AttributionOutputsChunk {
            attributed_breakdown_key_bits: bk,
            capped_attributed_trigger_value: tv,
        })
    }
}

/// A vector of histogram contributions for each output bucket.
///
/// Aggregation is vectorized over histogram buckets, so bit 0 for every histogram bucket is stored
/// contiguously, followed by bit 1 for each histogram bucket, etc.
pub type AggResult<const B: usize> = Result<BitDecomposed<Replicated<Boolean, B>>, Error>;

/// Returns a suitable proof chunk size (in records) for use with `aggregate_values`.
///
/// Let $N$ be the number of inputs, $k = \log N$, and $b$ be the input bit width. The
/// number of multiplies to aggregate a single column (neglecting the effect of
/// saturating the output) is:
///
/// $\sum_{i = 1}^k 2^{k - i} (b + i - 1) \approx 2^k (b + 1) = N (b + 1)$
pub fn aggregate_values_proof_chunk(input_width: usize, input_item_bits: usize) -> usize {
    max(2, TARGET_PROOF_SIZE / input_width / (input_item_bits + 1)).next_power_of_two()
}

// This is the step count for AggregateChunkStep. We need it to size RecordId arrays.
// This value must be at least the log of the aggregation chunk size.
pub const AGGREGATE_DEPTH: usize = 24;

/// Aggregate output contributions
///
/// In the case of attribution, each item in `aggregated_stream` is a vector of values to be added
/// to the output histogram. The vector length is `B`, the number of breakdowns, and at most one
/// element is non-zero. In the case of `feature_label_dot_product`, each item in
/// `aggregated_stream` is one column of the feature matrix multiplied by one scalar element of the
/// label vector (indicating whether a conversion occurred). The vector length `B` is the number of
/// features.
///
/// `OV` is the output value type, which is called `HV` (histogram value) in the attribution
/// protocol. If the aggregated contributions for a bucket overflow the `OV` type, this
/// implementation saturates at the maximum value the type can represent. It is recommended
/// that clients select a query configuration that avoids the possibility of overflow.
///
/// It might be possible to save some cost by using naive wrapping arithmetic. Another
/// possibility would be to combine all carries into a single "overflow detected" bit.
#[tracing::instrument(name = "aggregate_values", skip_all, fields(num_rows = num_rows))]
pub async fn aggregate_values<'ctx, 'fut, C, OV, const B: usize>(
    ctx: C,
    mut aggregated_stream: Pin<Box<dyn Stream<Item = AggResult<B>> + Send + 'fut>>,
    mut num_rows: usize,
    record_ids: Option<&mut [RecordId; AGGREGATE_DEPTH]>,
) -> Result<BitDecomposed<Replicated<Boolean, B>>, Error>
where
    'ctx: 'fut,
    C: Context + 'ctx,
    OV: BooleanArray + U128Conversions,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<C, B>,
{
    // Step used to add trigger values.
    type AdditionStep = ThirtyTwoBitStep;
    assert!(
        OV::BITS <= AdditionStep::BITS,
        "{} not large enough to accommodate the sum of {} bit values",
        type_name::<AdditionStep>(),
        OV::BITS,
    );

    let mut record_id_store = None;
    let record_ids =
        record_ids.unwrap_or_else(|| record_id_store.insert([RecordId::FIRST; AGGREGATE_DEPTH]));

    let mut depth = 0;
    while num_rows > 1 {
        // Indeterminate TotalRecords is currently required because aggregation does not poll
        // futures in parallel (thus cannot reach a batch of records).
        //
        // We reduce pairwise, passing through the odd record at the end if there is one, so the
        // number of outputs (`next_num_rows`) gets rounded up. The number of addition operations
        // (number of used record IDs) gets rounded down.
        let par_agg_ctx = ctx
            .narrow(&AggregateChunkStep::from(depth))
            .set_total_records(TotalRecords::Indeterminate);
        let next_num_rows = (num_rows + 1) / 2;
        let base_record_id = record_ids[depth];
        record_ids[depth] += num_rows / 2;
        aggregated_stream = Box::pin(
            FixedLength::new(aggregated_stream, num_rows)
                .try_chunks(2)
                .enumerate()
                .then(move |(i, chunk_res)| {
                    let ctx = par_agg_ctx.clone();
                    let record_id = base_record_id + i;
                    async move {
                        match chunk_res {
                            Err(e) => {
                                // `e.0` contains any elements that `try_chunks` buffered before the
                                // error. We can drop them, since we don't try to recover from errors.
                                Err(e.1)
                            }
                            Ok(mut chunk_vec) if chunk_vec.len() == 1 => {
                                Ok(chunk_vec.pop().unwrap())
                            }
                            Ok(mut chunk_pair) => {
                                assert_eq!(chunk_pair.len(), 2);
                                let b = chunk_pair.pop().unwrap();
                                let a = chunk_pair.pop().unwrap();
                                if a.len() < usize::try_from(OV::BITS).unwrap() {
                                    // If we have enough output bits, add and keep the carry.
                                    let (mut sum, carry) = integer_add::<_, AdditionStep, B>(
                                        ctx.narrow(&AggregateValuesStep::Add),
                                        record_id,
                                        &a,
                                        &b,
                                    )
                                    .await?;
                                    sum.push(carry);
                                    Ok(sum)
                                } else {
                                    integer_sat_add::<C, AdditionStep, B>(
                                        ctx.narrow(&AggregateValuesStep::SaturatingAdd),
                                        record_id,
                                        &a,
                                        &b,
                                    )
                                    .await
                                }
                            }
                        }
                    }
                    .instrument(tracing::trace_span!(
                        "reduce",
                        depth = depth,
                        rows = num_rows,
                        record = u32::from(record_id),
                    ))
                }),
        );
        num_rows = next_num_rows;
        depth += 1;
    }

    let mut result = aggregated_stream
        .try_next()
        .await?
        .unwrap_or_else(|| BitDecomposed::new(iter::empty()));
    assert!(
        aggregated_stream.next().await.is_none(),
        "aggregation should not produce multiple outputs"
    );
    // If there were less than 2^(|ov| - |tv|) inputs, then we didn't add enough carries to produce
    // a full-length output, so pad the output now.
    result.resize(
        usize::try_from(OV::BITS).unwrap(),
        Replicated::<Boolean, B>::ZERO,
    );
    // Aggregation output to remain vectorized
    Ok(result)
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::cmp::min;

    use futures::{stream, StreamExt};
    use proptest::prelude::*;

    use super::aggregate_values;
    use crate::{
        const_assert,
        error::Error,
        ff::{boolean::Boolean, boolean_array::BA8},
        helpers::Role,
        secret_sharing::{BitDecomposed, SharedValue},
        test_executor::run,
        test_fixture::{ReconstructArr, Runner, TestWorld},
    };

    fn input_row<const B: usize>(tv_bits: usize, values: &[u32]) -> BitDecomposed<[Boolean; B]> {
        let values = <&[u32; B]>::try_from(values).unwrap();

        BitDecomposed::decompose(tv_bits, |i| {
            values.map(|v| Boolean::from((v >> i) & 1 == 1))
        })
    }

    #[test]
    fn aggregate_even() {
        // Test aggregation with clean log2 structure
        run(|| async move {
            let inputs = vec![
                Ok(input_row(1, &[0, 0, 1, 1, 0, 1, 0, 1])),
                Ok(input_row(1, &[0, 1, 0, 1, 0, 1, 1, 0])),
                Ok(input_row(1, &[0, 0, 1, 1, 1, 0, 1, 1])),
                Ok(input_row(1, &[0, 0, 0, 0, 0, 0, 1, 1])),
                Ok(input_row(1, &[0, 0, 0, 0, 1, 1, 0, 1])),
                Ok(input_row(1, &[0, 0, 0, 0, 0, 1, 1, 1])),
                Ok(input_row(1, &[0, 0, 0, 0, 1, 1, 1, 1])),
                Ok(input_row(1, &[0, 0, 0, 0, 1, 0, 1, 1])),
            ];
            let result: BitDecomposed<BA8> = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();
            let expected: BitDecomposed<BA8> = input_row(8, &[0u32, 1, 2, 3, 4, 5, 6, 7])
                .map(|x: [Boolean; 8]| x.into_iter().collect::<BA8>());
            assert_eq!(result, expected);
        });
    }

    #[test]
    fn aggregate_odd() {
        // Test aggregation with odd number of records
        run(|| async move {
            let inputs = vec![
                Ok(input_row(1, &[0, 0, 1, 1, 0, 0, 0, 0])),
                Ok(input_row(1, &[0, 1, 0, 1, 0, 0, 0, 0])),
                Ok(input_row(1, &[0, 0, 1, 1, 0, 0, 0, 0])),
            ];
            let result = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();

            assert_eq!(
                result,
                input_row(8, &[0u32, 1, 2, 3, 0, 0, 0, 0])
                    .map(|x: [Boolean; 8]| x.into_iter().collect::<BA8>())
            );
        });
    }

    #[test]
    fn aggregate_multi_bit() {
        // Test aggregation with multi-bit trigger values
        run(|| async move {
            let inputs = vec![
                Ok(input_row(3, &[0, 0, 2, 1, 1, 2, 4, 0])),
                Ok(input_row(3, &[0, 1, 0, 1, 0, 2, 0, 7])),
                Ok(input_row(3, &[0, 0, 0, 1, 3, 1, 2, 0])),
            ];
            let result = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();

            assert_eq!(
                result,
                input_row(8, &[0u32, 1, 2, 3, 4, 5, 6, 7])
                    .map(|x: [Boolean; 8]| x.into_iter().collect::<BA8>())
            );
        });
    }

    #[test]
    fn aggregate_wide() {
        // Test aggregation with wide trigger values
        // (i.e. carries not preserved throughout aggregation)
        run(|| async move {
            let inputs = vec![
                Ok(input_row(7, &[0, 0, 2, 1, 1, 0, 1, 1])),
                Ok(input_row(7, &[0, 1, 0, 0, 2, 2, 1, 2])),
                Ok(input_row(7, &[0, 0, 0, 1, 1, 1, 2, 3])),
                Ok(input_row(7, &[0, 0, 0, 1, 0, 2, 2, 1])),
            ];
            let result = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();

            assert_eq!(
                result,
                input_row(8, &[0u32, 1, 2, 3, 4, 5, 6, 7])
                    .map(|x: [Boolean; 8]| x.into_iter().collect::<BA8>())
            );
        });
    }

    #[test]
    fn aggregate_saturating() {
        // Test that aggregation uses saturating addition
        run(|| async move {
            let inputs = vec![
                Ok(input_row(7, &[0x7f, 0x40, 0x7f, 0x7f, 0, 0, 0, 0])),
                Ok(input_row(7, &[0x7f, 0x40, 0x7f, 1, 0, 0, 0, 0])),
                Ok(input_row(7, &[1, 0x40, 0x7f, 0x7f, 0, 0, 0, 0])),
                Ok(input_row(7, &[0, 0x40, 0x7f, 1, 0, 0, 0, 0])),
            ];
            let result = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();

            assert_eq!(
                result,
                input_row(8, &[0xff_u32, 0xff, 0xff, 0xff, 0, 0, 0, 0])
                    .map(|x: [Boolean; 8]| x.into_iter().collect::<BA8>())
            );
        });
    }

    #[test]
    fn aggregate_empty() {
        run(|| async move {
            let result = TestWorld::default()
                .dzkp_semi_honest((), |ctx, ()| {
                    aggregate_values::<_, BA8, 8>(ctx, stream::empty().boxed(), 0, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();

            assert!(result.iter().all(|b| *b == 0));
        });
    }

    #[test]
    fn aggregate_error() {
        // Test aggregation with an error in the input stream
        run(|| async move {
            let inputs = vec![
                Ok(input_row(1, &[0, 0, 0, 0, 0, 0, 0, 0])),
                Err(Error::Internal),
            ];
            let result = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await;

            for &role in Role::all() {
                assert!(matches!(result[role], Err(Error::Internal)));
            }
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "FixedLength stream ended with 1 remaining")]
    fn aggregate_too_few() {
        // Test aggregation with less records than expected
        run(|| async move {
            let inputs = vec![Ok(input_row(1, &[0, 0, 1, 1, 0, 0, 0, 0]))];
            let _ = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len() + 1;
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();
        });
    }

    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "FixedLength stream ended with -1 remaining")]
    fn aggregate_too_many() {
        // Test aggregation with more records than expected
        run(|| async move {
            let inputs = vec![
                Ok(input_row(1, &[0, 0, 1, 1, 0, 0, 0, 0])),
                Ok(input_row(1, &[0, 1, 0, 1, 0, 0, 0, 0])),
                Ok(input_row(1, &[0, 0, 1, 1, 0, 0, 0, 0])),
            ];
            let _ = TestWorld::default()
                .dzkp_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len() - 1;
                    aggregate_values::<_, BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows, None)
                })
                .await
                .map(Result::unwrap)
                .reconstruct_arr();
        });
    }

    // Any of the supported aggregation configs can be used here (search for "aggregation output" in
    // transpose.rs). This small config keeps CI runtime within reason, however, it does not exercise
    // saturated addition at the output.
    const PROP_MAX_INPUT_LEN: usize = 10;
    const PROP_MAX_TV_BITS: usize = 3; // Limit: (1 << TV_BITS) must fit in u32
    const PROP_BUCKETS: usize = 8;
    type PropHistogramValue = BA8;

    // We want to capture everything in this struct for visibility in the output of failing runs,
    // even if it isn't used by the test.
    #[allow(dead_code)]
    #[derive(Debug)]
    struct AggregatePropTestInputs {
        inputs: Vec<[u32; PROP_BUCKETS]>,
        expected: BitDecomposed<PropHistogramValue>,
        len: usize,
        tv_bits: usize,
    }

    const_assert!(
        PropHistogramValue::BITS < u32::BITS,
        "(1 << PropHistogramValue::BITS) must fit in u32",
    );

    prop_compose! {
        fn arb_aggregate_values_inputs(max_len: usize)
                                      (
                                          len in 0..=max_len,
                                          tv_bits in 0..=PROP_MAX_TV_BITS,
                                      )
                                      (
                                          len in Just(len),
                                          tv_bits in Just(tv_bits),
                                          inputs in prop::collection::vec(prop::array::uniform(0u32..1 << tv_bits), len),
                                      )
        -> AggregatePropTestInputs {
            let mut expected = vec![0; PROP_BUCKETS];
            for row in &inputs {
                for (exp, val) in expected.iter_mut().zip(row) {
                    *exp = min(*exp + val, (1 << PropHistogramValue::BITS) - 1);
                }
            }

            let expected = input_row::<PROP_BUCKETS>(usize::try_from(PropHistogramValue::BITS).unwrap(), &expected)
                .map(|x| x.into_iter().collect());

            AggregatePropTestInputs {
                inputs,
                expected,
                len,
                tv_bits,
            }
        }
    }

    proptest! {
        #[test]
        fn aggregate_proptest(
            input_struct in arb_aggregate_values_inputs(PROP_MAX_INPUT_LEN),
            seed in any::<u64>(),
        ) {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let AggregatePropTestInputs {
                    inputs,
                    expected,
                    tv_bits,
                    ..
                } = input_struct;
                let inputs = inputs.into_iter().map(move |row| {
                    Ok(input_row(tv_bits, &row))
                });
                let result: BitDecomposed<PropHistogramValue> = TestWorld::with_seed(seed)
                    .dzkp_semi_honest(inputs, |ctx, inputs| {
                        let num_rows = inputs.len();
                        aggregate_values::<_, PropHistogramValue, PROP_BUCKETS>(
                            ctx,
                            stream::iter(inputs).boxed(),
                            num_rows,
                            None,
                        )
                    })
                    .await
                    .map(Result::unwrap)
                    .reconstruct_arr();

                assert_eq!(result, expected);
            });
        }
    }
}
