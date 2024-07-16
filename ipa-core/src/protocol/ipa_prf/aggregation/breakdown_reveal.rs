use std::{marker::PhantomData, mem};

use futures::{future, stream, stream::iter as stream_iter};
use futures_util::{StreamExt, TryStreamExt};
use tracing::{info_span, Instrument};

use super::step::AggregateValuesStep;
use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BooleanArray, BA64},
        ArrayAccess, U128Conversions,
    },
    helpers::TotalRecords,
    protocol::{
        basics::reveal,
        boolean::step::SixteenBitStep,
        context::{Context, UpgradedSemiHonestContext},
        ipa_prf::{
            aggregation::step::AggregationStep,
            boolean_ops::addition_sequential::{integer_add, integer_sat_add},
            prf_sharding::SecretSharedAttributionOutputs,
            shuffle::shuffle_attribution_outputs,
            BreakdownKey,
        },
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, BitDecomposed, Vectorizable,
    },
    seq_join::{seq_join, SeqJoin},
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
    let grouped_tvs = reveal_breakdowns::<HV, _, _, B>(&ctx, atributions).await?;
    add_tvs_by_bk::<TV, HV, B>(&ctx, grouped_tvs).await
}

/// Shuffles attribution Breakdown key and Trigger Value secret shares. Input
/// and output are the same type.
///
/// TODO: Use a more constrained BA type to contain BK and TV
/// TODO: Sharded shuffle
async fn shuffle_attributions<BK, TV, const B: usize>(
    parent_ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    contribs: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<SecretSharedAttributionOutputs<BK, TV>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
{
    let shuffle_ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean> =
        parent_ctx.narrow(&AggregationStep::Shuffle);
    shuffle_attribution_outputs::<_, BK, TV, BA64>(shuffle_ctx, contribs).await
}

/// Transforms the Breakdown key from a secret share into a revealed `usize`.
/// The input are the Atrributions and the output is a list of lists of secret
/// shared Trigger Values. Since Breakdown Keys are assumed to be dense the
/// first list contains all the possible Breakdowns, the index in the list
/// representing the Breakdown value. The second list groups all the Trigger
/// Values for that particular Breakdown.
///
/// TODO: Vectorize
/// TODO: Trace number of TVs
#[tracing::instrument(name = "reveal_breakdowns", skip_all)]
async fn reveal_breakdowns<HV, BK, TV, const B: usize>(
    parent_ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    attributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<GroupedTriggerValues<HV, B>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray,
{
    let reveal_ctx = parent_ctx
        .narrow(&AggregationStep::RevealStep)
        .set_total_records(TotalRecords::specified(attributions.len())?);

    let reveal_work = stream::iter(attributions).enumerate().map(|(i, ao)| {
        let record_id = RecordId::from(i);
        let reveal_ctx = reveal_ctx.clone();
        async move {
            let revealed_bk =
                reveal(reveal_ctx, record_id, &ao.attributed_breakdown_key_bits).await?;
            let revealed_bk: BK = BK::from_array(&revealed_bk);
            let Ok(bk) = usize::try_from(revealed_bk.as_u128()) else {
                return Err(Error::Internal);
            };
            Ok::<(usize, Replicated<TV>), Error>((bk, ao.capped_attributed_trigger_value))
        }
    });
    let tv_size: usize = TV::BITS.try_into().unwrap();
    let mut grouped_tvs = GroupedTriggerValues::<HV, B>::new(tv_size);
    let tvs: Vec<(usize, Replicated<TV>)> = seq_join(reveal_ctx.active_work(), reveal_work)
        .try_collect()
        .await?;
    for (bk, tv) in tvs {
        // Transpose 2
        // [Replicated<Boolean>;2].transpose() -> Replicated<Boolean, N=2>
        grouped_tvs.push(bk, tv.to_bits());
    }
    Ok(grouped_tvs)
}

type Operand = BitDecomposed<Replicated<Boolean>>;

/// Helper type that hold all the Trigger Values, grouped by their Breakdown
/// Key. Since the addition of 2 TVs returns a newly alloc TV and the number of
/// BKs is small, there's not a lot of gain by doing operations in place in
/// this structure.
struct GroupedTriggerValues<HV, const B: usize> {
    singles: [Option<Operand>; B],
    pairs: Vec<Pair>,
    size: usize,
    phantom: PhantomData<HV>,
}

impl<HV, const B: usize> GroupedTriggerValues<HV, B>
where
    Boolean: Vectorizable<1>,
    HV: BooleanArray,
{
    fn new(size: usize) -> Self {
        Self {
            singles: std::array::from_fn(|_| None),
            pairs: vec![],
            size,
            phantom: PhantomData,
        }
    }

    fn push(&mut self, bk: usize, value: Operand) {
        assert_eq!(self.size, value.len());
        let op = self.singles[bk].take();
        if let Some(existing_value) = op {
            self.pairs.push(Pair {
                left: existing_value,
                right: value,
                bk,
            });
            self.singles[bk] = None;
        } else {
            self.singles[bk] = Some(value);
        }
    }

    fn expand(&mut self) -> bool {
        let hv_size: usize = HV::BITS.try_into().unwrap();
        if self.size >= hv_size {
            return false;
        }
        self.size += 1;
        for so in &mut self.singles {
            if let Some(ref mut existing_s) = so.as_mut() {
                existing_s.push(Replicated::ZERO);
            }
        }
        true
    }
}

struct Pair {
    left: Operand,
    right: Operand,
    bk: usize,
}

/// We're adding two operands at a time which causes the "reduce" operation to
/// consume log(N) steps, with N being the number of events. The worst case is
/// all N entries in one BK.
pub const MAX_DEPTH: usize = 64;

/// Uses `reveal_breakdown` results as input which is all the Trigger Values
/// (N total), grouped by their Breakdown Key:
///
/// | BK  |      AdditiveShare(TV)      |
/// |-----|-----------------------------|
/// |   0 | \[(2, 3), (0, 5)]                |
/// |   1 | \[\]                          |
/// |   2 | \[0\]                         |
/// |   3 | \[(0, 2), (3, 5), (0, 7), (1, 2), 0\] |
/// | ... |                             |
/// | 255 | \[(3, 1), (0, 0)\]                |
///
/// This function operates on a loop (at most `log(N)` iterations), where on
/// each step we add together the pairs under a breakdown key until there are
/// no more pairs, meaning 0 or 1 value under each Breakdown Key. Following is
/// what one step of the iteration renders from the example above:
///
/// | BK  | AdditiveShare(TV) |
/// |-----|-----------------|
/// |   0 | \[(5, 5\)]          |
/// |   1 | \[\]              |
/// |   2 | \[0\]             |
/// |   3 | \[2, 8, 7, 3, 0\] |
/// | ... |                 |
/// | 255 | \[4, 0\]          |
///
/// Sharded version: Each shard simply operates on the Attribution Outputs it
/// has and then there's a final aggregation across done by the leader. This
/// approach is simple and doesn't need additional communication to distribute.
///
/// TODO: Vectorize. Take all SumPairs for the same size, chunk and add them.
/// TODO: Being a stream of futures allows to start computations earlier, but
/// need to keep track of the size of the resulting pair.
#[tracing::instrument(name = "add_tvs_by_bk", skip_all)]
async fn add_tvs_by_bk<TV, HV, const B: usize>(
    parent_ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    mut grouped_tvs: GroupedTriggerValues<HV, B>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    TV: BooleanArray,
    HV: BooleanArray,
{
    for d in 0..MAX_DEPTH {
        let pairs = mem::take(&mut grouped_tvs.pairs);
        // Exit condition
        if pairs.is_empty() {
            let mut r: Vec<Replicated<HV>> = vec![];
            for s in grouped_tvs.singles {
                if let Some(hv_bits) = s {
                    r.push(hv_bits.collect_bits());
                } else {
                    r.push(Replicated::ZERO);
                }
            }
            return Ok(r);
        }

        let can_expand = grouped_tvs.expand();

        let add_ctx = parent_ctx
            .narrow(&AggregationStep::Aggregate(d))
            .set_total_records(TotalRecords::specified(pairs.len()).unwrap());

        let work = pairs.iter().enumerate().map(|(i, p)| {
            let record_id = RecordId::from(i);
            let i_ctx = add_ctx.clone();
            // This is the work that will be executed in the future by seq_join
            // Returns a pair with the BK and the sum
            async move {
                if can_expand {
                    let (mut sum, carry) = integer_add::<_, SixteenBitStep, 1>(
                        i_ctx.narrow(&AggregateValuesStep::Add),
                        record_id,
                        &p.left,
                        &p.right,
                    )
                    .await?;
                    sum.push(carry);
                    Ok::<_, Error>((p.bk, sum))
                } else {
                    Ok((
                        p.bk,
                        integer_sat_add::<_, SixteenBitStep, 1>(
                            i_ctx.narrow(&AggregateValuesStep::SaturatingAdd),
                            record_id,
                            &p.left,
                            &p.right,
                        )
                        .await?,
                    ))
                }
            }
        });
        seq_join(add_ctx.active_work(), stream_iter(work))
            .try_for_each(|(bk, r)| {
                grouped_tvs.push(bk, r);
                future::ok(())
            })
            .instrument(info_span!(
                "add_tvs_reduce",
                depth = d,
                max_breakdowns = B,
                pairs_len = pairs.len(),
            ))
            .await?;
    }
    // Should never come to this. Insted it should return from the exit
    // condition in the for loop.
    Err(Error::Internal)
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
