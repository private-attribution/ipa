use std::{
    convert::Infallible,
    iter::{self, repeat},
    pin::Pin,
};

use futures::{Stream, StreamExt, TryStreamExt};
use ipa_macros::Step;

use crate::{
    error::{Error, LengthError, UnwrapInfallible},
    ff::{boolean::Boolean, CustomArray, U128Conversions},
    helpers::{
        stream::{process_stream_by_chunks, Chunk, ChunkBuffer, TryFlattenItersExt},
        TotalRecords,
    },
    protocol::{
        basics::{BooleanArrayMul, BooleanProtocols},
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::{
            boolean_ops::addition_sequential::integer_add, prf_sharding::AttributionOutputs,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        SharedValue, TransposeFrom, Vectorizable,
    },
    sharding::NotSharded,
};

mod bucket;

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
        let mut bk = BitDecomposed::new(
            repeat(Replicated::<Boolean, N>::ZERO).take(usize::try_from(BK::BITS).unwrap()),
        );
        bk.transpose_from(&self.attributed_breakdown_key_bits)?;
        let mut tv = BitDecomposed::new(
            repeat(Replicated::<Boolean, N>::ZERO).take(usize::try_from(TV::BITS).unwrap()),
        );
        tv.transpose_from(&self.capped_attributed_trigger_value)?;
        self.attributed_breakdown_key_bits = Vec::with_capacity(N);
        self.capped_attributed_trigger_value = Vec::with_capacity(N);
        Ok(AttributionOutputsChunk {
            attributed_breakdown_key_bits: bk,
            capped_attributed_trigger_value: tv,
        })
    }
}

#[derive(Step)]
pub(crate) enum Step {
    MoveToBucket,
    #[dynamic(32)]
    Aggregate(usize),
}

// Aggregation
//
// The input to aggregation is a stream of tuples of (attributed breakdown key, attributed trigger
// value) for each record.
//
// The first stage of aggregation decodes the breakdown key to produce a vector of trigger value
// to be added to each output bucket. At most one element of this vector can be non-zero,
// corresponding to the breakdown key value. This stage is implemented by the
// `move_single_value_to_bucket` function.
//
// The second stage of aggregation sums these vectors across all records, to produce the final
// output histogram.
//
// The first stage of aggregation is vectorized over records, meaning that a chunk of N
// records is collected, and the `move_single_value_to_bucket` function is called to
// decode the breakdown keys for all of those records simultaneously.
//
// The second stage of aggregation is vectorized over histogram buckets, meaning that
// the values in all `B` output buckets are added simultaneously.
//
// An intermediate transpose occurs between the two stages of aggregation, to convert from the
// record-vectorized representation to the bucket-vectorized representation.
//
// The input to this transpose is `&[BitDecomposed<AdditiveShare<Boolean, {agg chunk}>>]`, indexed
// by buckets, bits of trigger value, and contribution rows.
//
// The output is `&[BitDecomposed<AdditiveShare<Boolean, {buckets}>>]`, indexed by
// contribution rows, bits of trigger value, and buckets.
pub async fn aggregate_contributions<'ctx, St, BK, TV, HV, const B: usize, const N: usize>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
    contributions_stream: St,
    contributions_stream_len: usize,
) -> Result<Vec<Replicated<HV>>, Error>
where
    St: Stream<Item = Result<AttributionOutputs<Replicated<BK>, Replicated<TV>>, Error>> + Send,
    BK: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    TV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    HV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<N> + FieldSimd<B>,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, Boolean, B>,
    Replicated<BK>: BooleanArrayMul,
    Replicated<TV>: BooleanArrayMul,
    BitDecomposed<Replicated<Boolean, N>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<BK>>, Error = LengthError>,
    BitDecomposed<Replicated<Boolean, N>>:
        for<'a> TransposeFrom<&'a Vec<Replicated<TV>>, Error = LengthError>,
    Vec<BitDecomposed<Replicated<Boolean, B>>>:
        for<'a> TransposeFrom<&'a [BitDecomposed<Replicated<Boolean, N>>], Error = Infallible>,
    Vec<Replicated<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    let num_chunks = (contributions_stream_len + N - 1) / N;
    // Indeterminate TotalRecords is currently required because aggregation does not poll futures in
    // parallel (thus cannot reach a batch of records).
    let bucket_ctx = ctx
        .narrow(&Step::MoveToBucket)
        .set_total_records(TotalRecords::Indeterminate);
    // move each value to the correct bucket
    let row_contributions_stream = process_stream_by_chunks(
        contributions_stream,
        AttributionOutputs {
            attributed_breakdown_key_bits: vec![],
            capped_attributed_trigger_value: vec![],
        },
        move |idx, chunk: AttributionOutputsChunk<N>| {
            let record_id = RecordId::from(idx);
            let ctx = bucket_ctx.clone();
            async move {
                bucket::move_single_value_to_bucket::<_, N>(
                    ctx,
                    record_id,
                    chunk.attributed_breakdown_key_bits,
                    chunk.capped_attributed_trigger_value,
                    B,
                    false,
                )
                .await
            }
        },
        || AttributionOutputs {
            attributed_breakdown_key_bits: Replicated::ZERO,
            capped_attributed_trigger_value: Replicated::ZERO,
        },
    )
    .then(|fut| async move { fut.await.map(Chunk::into_raw) });

    let aggregation_input = Box::pin(
        row_contributions_stream
            .map_ok(|chunk| {
                // Aggregation intermediate transpose
                Vec::transposed_from(chunk.as_slice()).unwrap_infallible()
            })
            .try_flatten_iters::<BitDecomposed<_>, Vec<_>>(),
    );

    aggregate_values::<_, B>(ctx, aggregation_input, num_chunks * N).await
}

pub type AggResult<const B: usize> = Result<BitDecomposed<Replicated<Boolean, B>>, Error>;

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
/// protocol.
pub async fn aggregate_values<'ctx, 'fut, OV, const B: usize>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
    mut aggregated_stream: Pin<Box<dyn Stream<Item = AggResult<B>> + Send + 'fut>>,
    mut num_rows: usize,
) -> Result<Vec<Replicated<OV>>, Error>
where
    'ctx: 'fut,
    OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>:
        BooleanProtocols<UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>, Boolean, B>,
    Vec<Replicated<OV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<Replicated<Boolean, B>>, Error = LengthError>,
{
    let mut depth = 0;
    while num_rows > 1 {
        // We reduce pairwise, passing through the odd record at the end if there is one, so the
        // number of outputs (`num_rows`) gets rounded up. If calculating an explicit total
        // records, that would get rounded down.
        let par_agg_ctx = ctx
            .narrow(&Step::Aggregate(depth))
            .set_total_records(TotalRecords::Indeterminate);
        num_rows = (num_rows + 1) / 2;
        aggregated_stream = Box::pin(aggregated_stream.try_chunks(2).enumerate().then(
            move |(i, chunk_res)| {
                let ctx = par_agg_ctx.clone();
                async move {
                    match chunk_res {
                        Err(e) => {
                            // `e.0` contains any elements that `try_chunks` buffered before the
                            // error. We can drop them, since we don't try to recover from errors.
                            Err(e.1)
                        }
                        Ok(mut chunk_vec) if chunk_vec.len() == 1 => Ok(chunk_vec.pop().unwrap()),
                        Ok(mut chunk_pair) => {
                            assert_eq!(chunk_pair.len(), 2);
                            let b = chunk_pair.pop().unwrap();
                            let a = chunk_pair.pop().unwrap();
                            let (mut sum, carry) =
                                integer_add::<_, _, _, _, B>(ctx, RecordId::from(i), &a, &b)
                                    .await?;
                            if a.len() < usize::try_from(OV::BITS).unwrap() {
                                sum.push(carry);
                            }
                            Ok(sum)
                        }
                    }
                }
            },
        ));
        depth += 1;
    }

    let mut result: Vec<_> = aggregated_stream.try_collect().await?;
    assert!(result.len() <= 1);
    let mut result = result
        .pop()
        .unwrap_or_else(|| BitDecomposed::new(iter::empty()));
    result.resize(
        usize::try_from(OV::BITS).unwrap(),
        Replicated::<Boolean, B>::ZERO,
    );
    // Aggregation output transpose
    Ok(Vec::transposed_from(&result)?)
}

#[cfg(all(test, unit_test))]
pub mod tests {
    use std::{array, iter::repeat_with};

    use futures::{stream, StreamExt};
    use proptest::prelude::*;
    use rand::{rngs::StdRng, SeedableRng};

    use super::aggregate_values;
    use crate::{
        error::Error,
        ff::{boolean::Boolean, boolean_array::BA8, U128Conversions},
        helpers::Role,
        secret_sharing::BitDecomposed,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
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

            let result = TestWorld::default()
                .upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows)
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

            assert_eq!(result, [0u32, 1, 2, 3, 4, 5, 6, 7].map(BA8::truncate_from));
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
                .upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows)
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

            assert_eq!(result, [0u32, 1, 2, 3, 0, 0, 0, 0].map(BA8::truncate_from));
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
                .upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows)
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

            assert_eq!(result, [0u32, 1, 2, 3, 4, 5, 6, 7].map(BA8::truncate_from));
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
                .upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows)
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

            assert_eq!(result, [0u32, 1, 2, 3, 4, 5, 6, 7].map(BA8::truncate_from));
        });
    }

    #[test]
    fn aggregate_empty() {
        run(|| async move {
            let result = TestWorld::default()
                .upgraded_semi_honest((), |ctx, ()| {
                    aggregate_values::<BA8, 8>(ctx, stream::empty().boxed(), 0)
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

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
                .upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<BA8, 8>(ctx, stream::iter(inputs).boxed(), num_rows)
                })
                .await;

            for &role in Role::all() {
                assert!(matches!(result[role], Err(Error::Internal)));
            }
        });
    }

    // Any of the supported aggregation configs can be used here (search for "aggregation output" in
    // transpose.rs), but just doing this small config to keep CI runtime within reason.
    const PROP_MAX_INPUT_LEN: usize = 10;
    const PROP_MAX_TV_BITS: usize = 3;
    const PROP_BUCKETS: usize = 8;
    type PropHistogramValue = BA8;

    // We want to capture everything in this struct for visibility in the output of failing runs,
    // even if it isn't used by the test.
    #[allow(dead_code)]
    #[derive(Debug)]
    struct AggregatePropTestInputs {
        inputs: Vec<Result<BitDecomposed<[Boolean; PROP_BUCKETS]>, Error>>,
        expected: Vec<PropHistogramValue>,
        seed: u64,
        len: usize,
        tv_bits: usize,
    }

    prop_compose! {
        fn arb_aggregate_values_inputs(max_len: usize)
                                      (
                                          len in 0..=max_len,
                                          tv_bits in 0..=PROP_MAX_TV_BITS,
                                          seed in any::<u64>(),
                                      )
        -> AggregatePropTestInputs {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut expected = vec![0u32; PROP_BUCKETS];
            let inputs = repeat_with(|| {
                let row: [u32; PROP_BUCKETS] = array::from_fn(|_| rng.gen_range(0..1 << tv_bits));
                for (exp, val) in expected.iter_mut().zip(row) {
                    *exp += val;
                }
                Ok(input_row(tv_bits, &row))
            })
            .take(len)
            .collect();

            let expected = expected.into_iter().map(PropHistogramValue::truncate_from).collect();

            AggregatePropTestInputs {
                inputs,
                expected,
                seed,
                len,
                tv_bits,
            }
        }
    }
    proptest! {
        #[test]
        fn aggregate_proptest(
            input_struct in arb_aggregate_values_inputs(PROP_MAX_INPUT_LEN)
        ) {
            tokio::runtime::Runtime::new().unwrap().block_on(async {
                let AggregatePropTestInputs {
                    inputs,
                    expected,
                    ..
                } = input_struct;
                let result = TestWorld::default().upgraded_semi_honest(inputs.into_iter(), |ctx, inputs| {
                    let num_rows = inputs.len();
                    aggregate_values::<PropHistogramValue, PROP_BUCKETS>(
                        ctx,
                        stream::iter(inputs).boxed(),
                        num_rows,
                    )
                })
                .await
                .map(Result::unwrap)
                .reconstruct();

                assert_eq!(result, expected);
            });
        }
    }
}
