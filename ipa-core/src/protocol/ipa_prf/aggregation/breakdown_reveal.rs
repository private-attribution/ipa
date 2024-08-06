use std::mem;

use futures::{
    future,
    stream::{self, iter as stream_iter},
};
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
/// Aggregation steps happen after attribution. the input for Aggregation is a
/// list of tuples containing Trigger Values (TV) and their corresponding
/// Breakdown Keys (BK), which were attributed in the previous step of IPA. The
/// output of Aggregation is a histogram, where each “bin” or "bucket" is a BK
/// and the value is the addition of all the TVs for it, hence the name
/// Aggregation. This can be thought as a SQL GROUP BY operation.
///
/// The protocol involves four main steps:
/// 1. Add fake attribution outputs (DP noise). Not implemented.
/// 2. Shuffle the data to protect privacy (see [`shuffle_attributions`]).
/// 3. Reveal breakdown keys. This is the key difference to the previous
/// Aggregation (see [`reveal_breakdowns`]).
/// 4. Aggregate TVs by BKs (see [`add_tvs_by_bk`]).
pub async fn breakdown_reveal_aggregation<BK, TV, HV, const B: usize>(
    ctx: UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    atributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    BK: BreakdownKey<B>,
    TV: BooleanArray + U128Conversions,
    HV: BooleanArray + U128Conversions,
{
    let atributions = shuffle_attributions(&ctx, atributions).await?;
    let grouped_tvs = reveal_breakdowns(&ctx, atributions).await?;
    add_tvs_by_bk::<TV, HV, B>(&ctx, grouped_tvs).await
}

/// Shuffles attribution Breakdown key and Trigger Value secret shares. Input
/// and output are the same type.
///
/// TODO: Use a smaller BA type to contain BK and TV
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
/// ```rust, ignore
/// [Replicated<Boolean>;2].transpose() -> Replicated<Boolean, N=2>
/// ```
#[tracing::instrument(name = "reveal_breakdowns", skip_all, fields(
    total = attributions.len(),
))]
async fn reveal_breakdowns<BK, TV, const B: usize>(
    parent_ctx: &UpgradedSemiHonestContext<'_, NotSharded, Boolean>,
    attributions: Vec<SecretSharedAttributionOutputs<BK, TV>>,
) -> Result<GroupedTriggerValues<B>, Error>
where
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
    let mut grouped_tvs = GroupedTriggerValues::<B>::new(tv_size);
    let tvs: Vec<(usize, Replicated<TV>)> = seq_join(reveal_ctx.active_work(), reveal_work)
        .try_collect()
        .await?;
    for (bk, tv) in tvs {
        grouped_tvs.push(bk, tv.to_bits());
    }
    Ok(grouped_tvs)
}

/// Shorthand for TVs
type Operand = BitDecomposed<Replicated<Boolean>>;

/// Helper type that hold all the Trigger Values, grouped by their Breakdown
/// Key. They can either be in the singles array or as pairs.
///
/// The most important functionality of this struct is
/// [`GroupedTriggerValues::push`].
///
/// Since the addition of 2 TVs returns a newly alloc TV and the number of
/// BKs is small, there's not a lot of gain by doing operations in place with
/// references in this structure.
struct GroupedTriggerValues<const B: usize> {
    singles: [Option<Operand>; B],
    pairs: Vec<Pair>,
    size: usize,
}

impl<const B: usize> GroupedTriggerValues<B>
where
    Boolean: Vectorizable<1>,
{
    fn new(size: usize) -> Self {
        Self {
            singles: std::array::from_fn(|_| None),
            pairs: vec![],
            size,
        }
    }

    /// The method first  validates that the incoming Operand is the correct
    /// size. If not, this indicates a programming error, hence this is an
    /// assertion (the assertion should never happen unless there's a bug).
    ///
    /// Push checks the `singles[bk]` entry, if there's `None` then we add
    /// `Some(tv)`. Otherwise if there was a value already, we take it (leaving
    /// `None` in its place) and add a new `Pair`.
    fn push(&mut self, bk: usize, value: Operand) {
        assert_eq!(self.size, value.len());
        if let Some(existing_value) = self.singles[bk].take() {
            self.pairs.push(Pair {
                left: existing_value,
                right: value,
                bk,
            });
        } else {
            self.singles[bk] = Some(value);
        }
    }

    /// Returns whether the Operands size is bellow the size of the Histogram
    /// Value. This is useful to know where we want to do normal additions
    /// (with a carry) or saturated additions once we have reached the size of
    /// HV.
    ///
    /// Besides that, if the size is bellow, it will grow all the contained
    /// singles by one Zero and increase the size by one. Size makes sure that
    /// only Operands with the correct size are pushed in.
    fn expand<HV: BooleanArray>(&mut self) -> bool {
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

    fn into_final_result<HV: BooleanArray>(self) -> Vec<Replicated<HV>> {
        let mut r = Vec::<Replicated<HV>>::with_capacity(B);
        for s in self.singles {
            r.push(s.map_or(Replicated::ZERO, BitDecomposed::collect_bits));
        }
        r
    }
}

/// Contains the 2 operands for the sum and the BK under which those 2 values
/// are situated.
struct Pair {
    left: Operand,
    right: Operand,
    bk: usize,
}

/// We're adding two operands at a time which causes the "reduce" operation to
/// consume log(N) steps, with N being the number of events. The worst case is
/// BK * log (N / BK) but since BK is a small constant we just use lon(N).
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
/// The following pseudocode illustrates what this function does:
///
/// ```rust,ignore
/// add_tvs_by_bks(gtv: GroupedTriggerValues) {
///     loop {
/// 	    pairs = take(gtv.pairs) // pairs are moved out, leaving gtv.pairs empty
/// 	    if pairs.empty() {
/// 	    	// we're done
/// 	    	return gtv.singles
///     	}
///     	for p in pairs {
///     		sum = add(p.left, p.right)
///     		gtv.push(p.bk, sum)
///     	}
///     }
/// }
/// ```
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
    mut grouped_tvs: GroupedTriggerValues<B>,
) -> Result<Vec<Replicated<HV>>, Error>
where
    TV: BooleanArray,
    HV: BooleanArray,
{
    for d in 0..MAX_DEPTH {
        let pairs = mem::take(&mut grouped_tvs.pairs);
        // Exit condition
        if pairs.is_empty() {
            return Ok(grouped_tvs.into_final_result());
        }

        let can_expand = grouped_tvs.expand::<HV>();

        let add_ctx = parent_ctx
            .narrow(&AggregationStep::Aggregate(d))
            .set_total_records(TotalRecords::specified(pairs.len()).unwrap());

        let pairs_len = pairs.len();
        let work = pairs.into_iter().enumerate().map(|(i, p)| {
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
                pairs_len
            ))
            .await?;
    }
    // This loop terminates if the number of steps exceeds 64, which means
    // processing more than 2^64 events that shouldn't happen in practice.
    panic!()
}

#[cfg(all(test, any(unit_test, feature = "shuttle")))]
pub mod tests {
    use rand::{seq::SliceRandom, Rng};

    use crate::{
        ff::{
            boolean_array::{BA3, BA5, BA8},
            U128Conversions,
        },
        protocol::ipa_prf::{
            aggregation::breakdown_reveal::breakdown_reveal_aggregation,
            prf_sharding::{AttributionOutputsTestInput, SecretSharedAttributionOutputs},
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
                    breakdown_reveal_aggregation::<BA5, BA3, BA8, 32>(ctx, aos)
                        .await
                        .unwrap()
                })
                .await
                .reconstruct();
            let result = result.iter().map(|&v| v.as_u128()).collect::<Vec<_>>();
            assert_eq!(32, result.len());
            assert_eq!(result, expectation);
        });
    }
}
