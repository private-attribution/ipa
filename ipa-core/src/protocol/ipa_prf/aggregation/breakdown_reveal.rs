use futures::{stream::Stream, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::{
        boolean::Boolean, boolean_array::BooleanArray, ArrayAccess, U128Conversions
    },
    helpers::{repeat_n, TotalRecords},
    protocol::{
        basics::Reveal, boolean::step::SixteenBitStep, context::{
            Context, UpgradedSemiHonestContext, 
        }, ipa_prf::{
            aggregation::step::{AggregateValuesStep, AggregationStep}, boolean_ops::{addition_sequential::integer_sat_add, expand_shared_array_in_place}, prf_sharding::{AttributionOutputs, SecretSharedAttributionOutputs}, shuffle::{base::shuffle, shuffle_inputs}, BreakdownKey
        }, RecordId
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, SharedValue,
    },
    sharding::NotSharded,
};


// Improved Aggregation a.k.a Aggregation revealing breakdown.
//
// The previous phase was attribution. The input to aggregation is a stream of 
// tuples of (attributed breakdown key, attributed trigger value) for each 
// record.
// The output is a Histogram. BKs are assigned by the advertiser and sent in 
// the input of IPA. BK values are expected to be dense.
// How breakdown keys are defined is out-of-scope.
//
// High level explanation of the protocol:
// 1. TODO: Add fake attribution outputs.
// 2. Shuffle.
// 3. Reveal breakdown. Trigger values are not revelaed.
// 4. Aggregation if trigger values secret shares.
//
// DP noise to histogram buckets will be added by the caller of this function.
// This because adding noise is really unrelated to how things are added up.
//
// For aggregation, we pad TV with zeroes until size of HV and add them together.
// 
// TODO: Expanding bits only as needed.
// TODO: seq_join(replace join) (see quicksort)
// TODO: Add vectorization + chunks. Change TotalRecords::Indeterminate
// TODO: Add sharding.
pub async fn breakdown_reveal_aggregation<'ctx, St, BK, TV, HV, const B: usize>(
    ctx: UpgradedSemiHonestContext<'ctx, NotSharded, Boolean>,
    contributions_stream: St,
    contributions_stream_len: usize,
) -> Result<Vec<Replicated<HV>>, Error>
where
St: Stream<Item = Result<SecretSharedAttributionOutputs<BK, TV>, Error>> + Send,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
{ 
    // Fake events might avois skews naturally
    // Validation: TV bits need to be smaller than HV
    // TODO: Maybe move this to the function contract
    let contribs: Vec<AttributionOutputs<Replicated<BK>, Replicated<TV>>> = contributions_stream.try_collect().await?;
    
    let shuffle_ctx = ctx.narrow(&AggregationStep::Shuffle)
                .set_total_records(TotalRecords::Indeterminate);
    //let shuffled = shuffle(shuffle_ctx, contribs).await?;
    
    // at what level do we want to start the paralelization
    let hv_size: usize = HV::BITS.try_into().unwrap();
    let mut result = repeat_n(BitDecomposed::new(repeat_n(Replicated::ZERO, hv_size)), B)
        .collect::<Vec<BitDecomposed<Replicated<Boolean>>>>();
    // for loop will be replaced with vectorized 
    for (i, attribution_outputs) in contribs.into_iter().enumerate() {
        let record_id = RecordId::from(i);
        let ao: AttributionOutputs<Replicated<BK>, Replicated<TV>> = attribution_outputs; // For Rust Analyzer
        let bk_share = ao.attributed_breakdown_key_bits;
        // reveal and get position in histogram
        let reveal_ctx = ctx.narrow(&AggregationStep::RevealStep)
            .set_total_records(TotalRecords::Indeterminate);
        let revealed_bk: BK = BK::from_array(&bk_share.reveal(reveal_ctx, record_id).await?);
        let pos = usize::try_from(revealed_bk.as_u128())?;
        tracing::info!("revealed_bk={pos}, tv={:?}", ao.capped_attributed_trigger_value);


        // split

        // expand trigger value to size of histogram value
        let tv: BitDecomposed<Replicated<Boolean>> = ao.capped_attributed_trigger_value.to_bits();
        
        let add_ctx = ctx.narrow(&AggregateValuesStep::Add)
            .set_total_records(TotalRecords::Indeterminate);
        // Number of steps depends on HV size
        // "merge sort"
        // b[0] + a[0]   
        let r = integer_sat_add::<_, SixteenBitStep, 1>(add_ctx, record_id, &result[pos], &tv).await?;
        result[pos] = r;
    }
    let resp: Vec<Replicated<HV>> = result
        .into_iter()
        .map(|b: BitDecomposed<Replicated<Boolean>>| b.collect_bits())
        .collect();
    Ok(resp)
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use futures::stream;

    use crate::{
        ff::{
            boolean_array::{BA16, BA3, BA5}, U128Conversions
        }, protocol::ipa_prf::{aggregation::breakdown_reveal::breakdown_reveal_aggregation, prf_sharding::AttributionOutputs}, secret_sharing::{
            replicated::semi_honest::AdditiveShare as Replicated, IntoShares,
        }, test_executor::run, test_fixture::{Reconstruct, Runner, TestWorld}
    };

    struct TestInput {
        pub bk: BA5,
        pub tv: BA3,
    }

    impl IntoShares<(Replicated<BA5>, Replicated<BA3>)> for TestInput {
        fn share_with<R: rand::Rng>(self, rng: &mut R) -> [(Replicated<BA5>, Replicated<BA3>); 3] {
            let bk_sh = self.bk.share_with(rng);
            let tv_sh = self.tv.share_with(rng);
            [
                (bk_sh[0].clone(), tv_sh[0].clone()), (bk_sh[1].clone(), tv_sh[1].clone()), (bk_sh[2].clone(), tv_sh[2].clone()),
            ]
        }
    }

    fn input_row(bk: u128, tv: u128) -> TestInput {
        TestInput {
            bk: BA5::truncate_from(bk), 
            tv: BA3::truncate_from(tv),
        }
    }

    // TODO: shuttle test: indeterminate, test deadlocks.

    #[test]
    fn semi_honest_happy_path() {
        run(|| async {
            let world = TestWorld::default();
            let inputs = vec![
                Ok(input_row(10, 2)),
                Ok(input_row(10, 1)),
                Ok(input_row(11, 4)),
                Ok(input_row(3, 5)),
                Ok(input_row(3, 2)),
                Ok(input_row(1, 3)),
                Ok(input_row(22, 5)),
                Ok(input_row(3, 1)),
                Ok(input_row(4, 3)),
                Ok(input_row(10, 2)),
            ];
            let result: Vec<_> = world
                .upgraded_semi_honest(inputs.into_iter(), |ctx, input_rows| async move {
                    let aos = input_rows.iter().flatten().map(|ti| Ok(AttributionOutputs {
                        attributed_breakdown_key_bits: ti.0.clone(),
                        capped_attributed_trigger_value: ti.1.clone(),
                    }));
                    breakdown_reveal_aggregation::<_, BA5, BA3, BA16, 32>(ctx, stream::iter(aos), input_rows.len())
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            let result = result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>();
            tracing::info!("result={:?}", result);
            assert_eq!(32, result.len());
            assert_eq!(result[0], 0);
            assert_eq!(result[1], 3);
            assert_eq!(result[3], 8);
            assert_eq!(result[4], 3);
            assert_eq!(result[10], 5);
            assert_eq!(result[11], 4);
            assert_eq!(result[22], 5);
        });
    }
}