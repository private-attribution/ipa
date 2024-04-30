use std::{convert::Infallible, iter::repeat, pin::Pin};

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
        context::UpgradedContext,
        ipa_prf::{
            boolean_ops::addition_sequential::integer_add, prf_sharding::AttributionOutputs,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, FieldSimd,
        SharedValue, TransposeFrom, Vectorizable,
    },
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
//
// The transpose operates on contribution rows and buckets. It proceeds identically for
// each trigger value bit, just like it does for the left and right shares. However, because
// the trigger value bits exist between the row and bucket indexing, a special transpose
// implementation is required for this case.
pub async fn aggregate_contributions<C, St, BK, TV, HV, const B: usize, const N: usize>(
    ctx: C,
    contributions_stream: St,
    contributions_stream_len: usize,
) -> Result<Vec<Replicated<HV>>, Error>
where
    C: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    St: Stream<Item = Result<AttributionOutputs<Replicated<BK>, Replicated<TV>>, Error>> + Send,
    BK: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    TV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    HV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<N> + FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<C, Boolean, B>,
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

    aggregate_values::<_, _, B>(ctx, aggregation_input, num_chunks * N).await
}

pub type AggResult<const B: usize> = Result<BitDecomposed<Replicated<Boolean, B>>, Error>;

pub async fn aggregate_values<'fut, C, OV, const B: usize>(
    ctx: C,
    mut aggregated_stream: Pin<Box<dyn Stream<Item = AggResult<B>> + Send + 'fut>>,
    mut num_rows: usize,
) -> Result<Vec<Replicated<OV>>, Error>
where
    C: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    OV: SharedValue + U128Conversions + CustomArray<Element = Boolean>,
    Boolean: FieldSimd<B>,
    Replicated<Boolean, B>: BooleanProtocols<C, Boolean, B>,
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
    assert_eq!(result.len(), 1);
    let mut result = result.pop().unwrap();
    result.resize(
        usize::try_from(OV::BITS).unwrap(),
        Replicated::<Boolean, B>::ZERO,
    );
    // Aggregation output transpose
    Ok(Vec::transposed_from(&result)?)
}
