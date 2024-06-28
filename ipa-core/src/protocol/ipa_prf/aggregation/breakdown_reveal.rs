use futures::{stream::Stream, TryStreamExt};

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA64},
        ArrayAccess, U128Conversions,
    },
    helpers::{repeat_n, TotalRecords},
    protocol::{
        basics::Reveal,
        boolean::step::SixteenBitStep,
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::{
            aggregation::step::AggregationStep, boolean_ops::addition_sequential::integer_sat_add,
            prf_sharding::SecretSharedAttributionOutputs, shuffle::shuffle_attribution_outputs,
            BreakdownKey,
        },
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed},
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
// TODO: Use sharded shuffle.
// TODO: Expanding bits only as needed.
// TODO: seq_join (see quicksort). First reveal, create futures for the remainder.
// TODO: Add vectorization + chunks. Change TotalRecords::Indeterminate. "Merge-sort".
// TODO: Add sharding.
pub async fn breakdown_reveal_aggregation<St, BK, TV, HV, const B: usize>(
    ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    contributions_stream: St,
) -> Result<Vec<Replicated<HV>>, Error>
where
    St: Stream<Item = Result<SecretSharedAttributionOutputs<BK, TV>, Error>> + Send,
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
{
    // TODO: Maybe move this to the function contract
    let contribs: Vec<_> = contributions_stream.try_collect().await?;
    let shuffle_ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean> =
        ctx.narrow(&AggregationStep::Shuffle);
    let contribs = shuffle_attribution_outputs::<_, BK, TV, BA64>(shuffle_ctx, contribs).await?;
    // at what level do we want to start the paralelization
    let hv_size: usize = HV::BITS.try_into().unwrap();
    let mut result = repeat_n(BitDecomposed::new(repeat_n(Replicated::ZERO, hv_size)), B)
        .collect::<Vec<BitDecomposed<Replicated<Boolean>>>>();
    // for loop will be replaced with vectorized
    for (i, attribution_outputs) in contribs.into_iter().enumerate() {
        let record_id = RecordId::from(i);
        let ao: SecretSharedAttributionOutputs<BK, TV> = attribution_outputs; // For Rust Analyzer
        let bk_share = ao.attributed_breakdown_key_bits;
        let reveal_ctx = ctx
            .narrow(&AggregationStep::RevealStep)
            .set_total_records(TotalRecords::Indeterminate);
        let revealed_bk: BK = BK::from_array(&bk_share.reveal(reveal_ctx, record_id).await?);
        let pos = usize::try_from(revealed_bk.as_u128())?;
        //tracing::info!("revealed_bk={pos}, tv={:?}", ao.capped_attributed_trigger_value);
        let tv: BitDecomposed<Replicated<Boolean>> = ao.capped_attributed_trigger_value.to_bits();
        let add_ctx = ctx
            .narrow(&AggregationStep::Add)
            .set_total_records(TotalRecords::Indeterminate);
        let r =
            integer_sat_add::<_, SixteenBitStep, 1>(add_ctx, record_id, &result[pos], &tv).await?;
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
            boolean_array::{BA16, BA3, BA5},
            U128Conversions,
        },
        protocol::ipa_prf::{
            aggregation::breakdown_reveal::breakdown_reveal_aggregation,
            prf_sharding::{AttributionOutputsTestInput, SecretSharedAttributionOutputs},
        },
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    fn input_row(bk: u128, tv: u128) -> AttributionOutputsTestInput<BA5, BA3> {
        AttributionOutputsTestInput {
            bk: BA5::truncate_from(bk),
            tv: BA3::truncate_from(tv),
        }
    }

    #[test]
    fn semi_honest_happy_path() {
        run(|| async {
            let world = TestWorld::default();
            let inputs = vec![
                input_row(10, 2),
                input_row(10, 1),
                input_row(11, 4),
                input_row(3, 5),
                input_row(3, 2),
                input_row(1, 3),
                input_row(22, 5),
                input_row(3, 1),
                input_row(4, 3),
                input_row(10, 2),
            ];
            let result: Vec<_> = world
                .upgraded_semi_honest(inputs.clone().into_iter(), |ctx, input_rows| async move {
                    let aos = input_rows.into_iter().map(|ti| {
                        Ok(SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                    });
                    breakdown_reveal_aggregation::<_, BA5, BA3, BA16, 32>(ctx, stream::iter(aos))
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
