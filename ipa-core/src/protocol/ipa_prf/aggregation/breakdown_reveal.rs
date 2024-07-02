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

/// Improved Aggregation a.k.a Aggregation revealing breakdown.
///
/// Aggregation steps happen after attribution. The input to aggregation is a
/// stream of tuples of (attributed breakdown key, attributed trigger value).
/// The output of aggregation is a Histogram. Breakdown Keys and Trigger Values
/// are assigned by the advertiser and sent in the input of IPA. Breakdown Keys
///  values are expected to be dense. How breakdown keys and trigger values are
///  defined is out-of-scope.
///
/// High level explanation of the protocol:
///
/// 1. Add fake attribution outputs.
/// 2. Shuffle.
/// 3. Reveal Breakdown Keys. By having shuffled and adding fake entries we
/// protected the identities of individuals. Trigger values are not revealed.
/// 4. Aggregation of Trigger Value by Breakdown Key (Think of group by).
pub async fn breakdown_reveal_aggregation<BK, TV, HV, const B: usize>(
    ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    atributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
{
    let atributions = shuffle_attributions::<_, _, B>(&ctx, atributions).await?;
    let grouped_tvs = reveal_breakdowns::<_, _, B>(&ctx, atributions).await?;
    add_tvs_by_bk(&ctx, grouped_tvs).await
}

/// Shuffles attribution Breakdown key and Trigger Value secret shares. Input
/// and output are the same type.
///
/// TODO: Use a more constrained BA type to contain BK and TV
/// TODO: Sharded shuffle
async fn shuffle_attributions<BK, TV, const B: usize>(
    ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    contribs: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<SecretSharedAttributionOutputs<BK, TV>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
{
    let shuffle_ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean> =
        ctx.narrow(&AggregationStep::Shuffle);
    shuffle_attribution_outputs::<_, BK, TV, BA64>(shuffle_ctx, contribs).await
}

/// Transforms the Breakdown key from a secret share into a revealed `usize`.
/// The input are the Atrributions and the output is a list of lists of secret
/// shared Trigger Values. Since Breakdown Keys are assumed to be dense the
/// first list contains all the possible Breakdowns, the index in the list
/// representing the Breakdown value. The second list groups all the Trigger
/// Values for that particular Breakdown.
///
/// TODO: TotalRecords::Indeterminate
/// TODO: Batch input into AGG vectorized and use `process_slice_by_chunks`
/// and `seq_join`.
#[tracing::instrument(name = "reveal_breakdowns", skip_all)]
async fn reveal_breakdowns<BK, TV, const B: usize>(
    ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    atributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<Vec<Replicated<TV>>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
{
    let mut grouped_tvs: Vec<Vec<Replicated<TV>>> = vec![vec![]; B];
    let reveal_ctx = ctx
        .narrow(&AggregationStep::RevealStep)
        .set_total_records(TotalRecords::Indeterminate);
    for (i, ao) in atributions.into_iter().enumerate() {
        let record_id = RecordId::from(i);
        let bk_share = ao.attributed_breakdown_key_bits;
        let revealed_bk: BK =
            BK::from_array(&bk_share.reveal(reveal_ctx.clone(), record_id).await?);
        let Ok(pos) = usize::try_from(revealed_bk.as_u128()) else {
            return Err(Error::Internal);
        };
        grouped_tvs[pos].push(ao.capped_attributed_trigger_value);
    }
    Ok(grouped_tvs)
}

/// Uses `reveal_breakdown` results as input. This will cycle through each
/// Breakdown, adding up all the Trigger Values. Returns the values for each
/// Breakdown.
///
/// TODO: TotalRecords::Indeterminate
/// TODO: Only expand bits as necessary. "Merge-sort" inspired.
/// TODO: Sharding strategy.
#[tracing::instrument(name = "add_tvs_by_bk", skip_all)]
async fn add_tvs_by_bk<TV, HV>(
    ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    grouped_tvs: Vec<Vec<Replicated<TV>>>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
{
    let add_ctx = ctx
        .narrow(&AggregationStep::Add)
        .set_total_records(TotalRecords::Indeterminate);
    let hv_size: usize = HV::BITS.try_into().unwrap();
    let mut sums_bits: Vec<Replicated<HV>> = vec![];
    let mut i: usize = 0;
    for bk in grouped_tvs {
        let mut sum_bits = BitDecomposed::new(repeat_n(Replicated::ZERO, hv_size));
        for tv in bk {
            let tv_bits: BitDecomposed<Replicated<Boolean>> = tv.to_bits();
            let record_id = RecordId::from(i);
            sum_bits = integer_sat_add::<_, SixteenBitStep, 1>(
                add_ctx.clone(),
                record_id,
                &sum_bits,
                &tv_bits,
            )
            .await?;
            i += 1;
        }
        let r: Replicated<HV> = sum_bits.collect_bits();
        sums_bits.push(r);
    }
    Ok(sums_bits)
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
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
                    let aos = input_rows
                        .into_iter()
                        .map(|ti| SecretSharedAttributionOutputs {
                            attributed_breakdown_key_bits: ti.0,
                            capped_attributed_trigger_value: ti.1,
                        })
                        .collect();
                    breakdown_reveal_aggregation::<BA5, BA3, BA16, 32>(ctx, aos)
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
