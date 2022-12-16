use super::{
    compute_b_bit, compute_stop_bit, AggregateCreditOutputRow, CappedCreditsWithAggregationBit,
    CreditCappingOutputRow, InteractionPatternStep,
};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::attribution::AttributionResharableStep::{
    AggregationBit, BreakdownKey, Credit, HelperBit,
};
use crate::protocol::basics::SecureMul;
use crate::protocol::boolean::{random_bits_generator::RandomBitsGenerator, BitDecomposition};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::modulus_conversion::transpose;
use crate::protocol::sort::apply_sort::apply_sort_permutation;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::sort::generate_permutation::generate_permutation_and_reveal_shuffled;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::Replicated;
use async_trait::async_trait;
use futures::future::{try_join, try_join_all};
use std::iter::repeat;

#[async_trait]
impl<F: Field + Sized> Resharable<F> for CappedCreditsWithAggregationBit<F> {
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_helper_bit = ctx
            .narrow(&HelperBit)
            .reshare(&self.helper_bit, record_id, to_helper);
        let f_aggregation_bit =
            ctx.narrow(&AggregationBit)
                .reshare(&self.aggregation_bit, record_id, to_helper);
        let f_breakdown_key =
            ctx.narrow(&BreakdownKey)
                .reshare(&self.breakdown_key, record_id, to_helper);
        let f_value = ctx
            .narrow(&Credit)
            .reshare(&self.credit, record_id, to_helper);

        let mut outputs =
            try_join_all([f_helper_bit, f_aggregation_bit, f_breakdown_key, f_value]).await?;

        Ok(CappedCreditsWithAggregationBit {
            helper_bit: outputs.remove(0),
            aggregation_bit: outputs.remove(0),
            breakdown_key: outputs.remove(0),
            credit: outputs.remove(0),
        })
    }
}

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
pub async fn aggregate_credit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    capped_credits: &[CreditCappingOutputRow<F>],
    max_breakdown_key: u128,
) -> Result<Vec<AggregateCreditOutputRow<F>>, Error> {
    let one = ctx.share_of_one();

    //
    // 1. Add aggregation bits and new rows per unique breakdown_key
    //
    let capped_credits_with_aggregation_bits =
        add_aggregation_bits_and_breakdown_keys(&ctx, capped_credits, max_breakdown_key);

    //
    // 2. Sort by `breakdown_key`. Rows with `aggregation_bit` = 0 must
    // precede all other rows in the input. (done in the previous step).
    //
    let sorted_input = sort_by_breakdown_key(
        ctx.narrow(&Step::SortByBreakdownKey),
        &capped_credits_with_aggregation_bits,
        max_breakdown_key,
    )
    .await?;

    //
    // 3. Aggregate by parallel prefix sum of credits per breakdown_key
    //
    //     b = current.stop_bit * successor.helper_bit;
    //     new_credit[current_index] = current.credit + b * successor.credit;
    //     new_stop_bit[current_index] = b * successor.stop_bit;
    //
    let num_rows = sorted_input.len();
    let mut stop_bits = repeat(one.clone()).take(num_rows).collect::<Vec<_>>();

    let mut credits = sorted_input
        .iter()
        .map(|x| x.credit.clone())
        .collect::<Vec<_>>();

    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let c = ctx.narrow(&InteractionPatternStep::from(depth));
        let mut futures = Vec::with_capacity(end);

        for i in 0..end {
            let c = c.clone();
            let record_id = RecordId::from(i);
            let sibling_helper_bit = &sorted_input[i + step_size].helper_bit;
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_credit = &credits[i + step_size];
            futures.push(async move {
                let b = compute_b_bit(
                    c.narrow(&Step::ComputeBBit),
                    record_id,
                    current_stop_bit,
                    sibling_helper_bit,
                    depth == 0,
                )
                .await?;

                try_join(
                    c.narrow(&Step::AggregateCreditBTimesSuccessorCredit)
                        .multiply(record_id, &b, sibling_credit),
                    compute_stop_bit(
                        c.narrow(&Step::ComputeStopBit),
                        record_id,
                        &b,
                        sibling_stop_bit,
                        depth == 0,
                    ),
                )
                .await
            });
        }

        let results = try_join_all(futures).await?;

        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                credits[i] += &credit;
                stop_bits[i] = stop_bit;
            });
    }

    // Prepare the sidecar for sorting
    let aggregated_credits = sorted_input
        .iter()
        .enumerate()
        .map(|(i, x)| CappedCreditsWithAggregationBit {
            helper_bit: x.helper_bit.clone(),
            aggregation_bit: x.aggregation_bit.clone(),
            breakdown_key: x.breakdown_key.clone(),
            credit: credits[i].clone(),
        })
        .collect::<Vec<_>>();

    //
    // 4. Sort by `aggregation_bit`
    //
    let sorted_output =
        sort_by_aggregation_bit(ctx.narrow(&Step::SortByAttributionBit), &aggregated_credits)
            .await?;

    // Take the first k elements, where k is the amount of breakdown keys.
    let result = sorted_output
        .iter()
        .take(max_breakdown_key.try_into().unwrap())
        .map(|x| AggregateCreditOutputRow {
            breakdown_key: x.breakdown_key.clone(),
            credit: x.credit.clone(),
        })
        .collect::<Vec<_>>();

    Ok(result)
}

fn add_aggregation_bits_and_breakdown_keys<F: Field>(
    ctx: &SemiHonestContext<'_, F>,
    capped_credits: &[CreditCappingOutputRow<F>],
    max_breakdown_key: u128,
) -> Vec<CappedCreditsWithAggregationBit<F>> {
    let zero = Replicated::ZERO;
    let one = ctx.share_of_one();

    // Unique breakdown_key values with all other fields initialized with 0's.
    // Since we cannot see the actual breakdown key values, we'll need to
    // append all possible values. For now, we assume breakdown_key is in the
    // range of (0..MAX_BREAKDOWN_KEY).
    let mut unique_breakdown_keys = (0..max_breakdown_key)
        .map(|i| CappedCreditsWithAggregationBit {
            helper_bit: zero.clone(),
            aggregation_bit: zero.clone(),
            breakdown_key: Replicated::from_scalar(ctx.role(), F::from(i)),
            credit: zero.clone(),
        })
        .collect::<Vec<_>>();

    // Add aggregation bits and initialize with 1's.
    unique_breakdown_keys.append(
        &mut capped_credits
            .iter()
            .map(|x| CappedCreditsWithAggregationBit {
                helper_bit: one.clone(),
                aggregation_bit: one.clone(),
                breakdown_key: x.breakdown_key.clone(),
                credit: x.credit.clone(),
            })
            .collect::<Vec<_>>(),
    );

    unique_breakdown_keys
}

async fn bit_decompose_breakdown_key<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CappedCreditsWithAggregationBit<F>],
) -> Result<Vec<Vec<Replicated<F>>>, Error> {
    let random_bits_generator = RandomBitsGenerator::new();
    try_join_all(
        input
            .iter()
            .zip(repeat(ctx))
            .enumerate()
            .map(|(i, (x, c))| {
                let rbg = random_bits_generator.clone();
                async move {
                    BitDecomposition::execute(c, RecordId::from(i), rbg, &x.breakdown_key).await
                }
            })
            .collect::<Vec<_>>(),
    )
    .await
}

async fn sort_by_breakdown_key<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CappedCreditsWithAggregationBit<F>],
    max_breakdown_key: u128,
) -> Result<Vec<CappedCreditsWithAggregationBit<F>>, Error> {
    // TODO: Change breakdown_keys to use XorReplicated to avoid bit-decomposition calls
    let breakdown_keys = transpose(
        &bit_decompose_breakdown_key(ctx.narrow(&Step::BitDecomposeBreakdownKey), input).await?,
    );

    // We only need to run a radix sort on the bits used by all possible
    // breakdown key values.
    let valid_bits_count = u128::BITS - (max_breakdown_key - 1).leading_zeros();

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByBreakdownKey),
        &breakdown_keys[..valid_bits_count as usize],
        valid_bits_count,
    )
    .await?;

    apply_sort_permutation(
        ctx.narrow(&Step::ApplyPermutationOnBreakdownKey),
        input.to_vec(),
        &sort_permutation,
    )
    .await
}

async fn sort_by_aggregation_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CappedCreditsWithAggregationBit<F>],
) -> Result<Vec<CappedCreditsWithAggregationBit<F>>, Error> {
    // Since aggregation_bit is a 1-bit share of 1 or 0, we'll just extract the
    // field and wrap it in another vector.
    let aggregation_bits = &[input
        .iter()
        .map(|x| x.aggregation_bit.clone())
        .collect::<Vec<_>>()];

    let sort_permutation = generate_permutation_and_reveal_shuffled(
        ctx.narrow(&Step::GeneratePermutationByAttributionBit),
        aggregation_bits,
        1,
    )
    .await?;

    apply_sort_permutation(
        ctx.narrow(&Step::ApplyPermutationOnAttributionBit),
        input.to_vec(),
        &sort_permutation,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ComputeBBit,
    ComputeStopBit,
    SortByBreakdownKey,
    SortByAttributionBit,
    AggregateCreditBTimesSuccessorCredit,
    BitDecomposeBreakdownKey,
    GeneratePermutationByBreakdownKey,
    ApplyPermutationOnBreakdownKey,
    GeneratePermutationByAttributionBit,
    ApplyPermutationOnAttributionBit,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ComputeBBit => "compute_b_bit",
            Self::ComputeStopBit => "compute_stop_bit",
            Self::SortByBreakdownKey => "sort_by_breakdown_key",
            Self::SortByAttributionBit => "sort_by_attribution_bit",
            Self::AggregateCreditBTimesSuccessorCredit => {
                "aggregate_credit_b_times_successor_credit"
            }
            Self::BitDecomposeBreakdownKey => "bit_decompose_breakdown_key",
            Self::GeneratePermutationByBreakdownKey => "generate_permutation_by_breakdown_key",
            Self::ApplyPermutationOnBreakdownKey => "apply_permutation_by_breakdown_key",
            Self::GeneratePermutationByAttributionBit => "generate_permutation_by_attribution_bit",
            Self::ApplyPermutationOnAttributionBit => "apply_permutation_on_attribution_bit",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
pub(crate) mod tests {
    use super::super::tests::{BD, H};
    use super::{aggregate_credit, sort_by_breakdown_key};
    use crate::ff::{Field, Fp31};
    use crate::protocol::attribution::accumulate_credit::tests::AttributionTestInput;
    use crate::protocol::attribution::{
        AggregateCreditOutputRow, CappedCreditsWithAggregationBit, CreditCappingOutputRow,
    };
    use crate::protocol::QueryId;
    use crate::rand::Rng;
    use crate::secret_sharing::{IntoShares, Replicated};
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use rand::{distributions::Standard, prelude::Distribution};

    // TODO: There are now too many xxxInputRow and yyyOutputRow. Combine them into one
    impl<F> IntoShares<CreditCappingOutputRow<F>> for AttributionTestInput<F>
    where
        F: Field + IntoShares<Replicated<F>>,
        Standard: Distribution<F>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [CreditCappingOutputRow<F>; 3] {
            let [b0, b1, b2] = self.0[1].share_with(rng);
            let [c0, c1, c2] = self.0[2].share_with(rng);
            [
                CreditCappingOutputRow {
                    breakdown_key: b0,
                    credit: c0,
                },
                CreditCappingOutputRow {
                    breakdown_key: b1,
                    credit: c1,
                },
                CreditCappingOutputRow {
                    breakdown_key: b2,
                    credit: c2,
                },
            ]
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [AggregateCreditOutputRow<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            [&self[0], &self[1], &self[2]].reconstruct()
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [&AggregateCreditOutputRow<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            let s0 = &self[0];
            let s1 = &self[1];
            let s2 = &self[2];

            let breakdown_key =
                (&s0.breakdown_key, &s1.breakdown_key, &s2.breakdown_key).reconstruct();
            let credit = (&s0.credit, &s1.credit, &s2.credit).reconstruct();

            AttributionTestInput([breakdown_key, credit, F::ZERO, F::ZERO])
        }
    }

    impl<F> IntoShares<CappedCreditsWithAggregationBit<F>> for AttributionTestInput<F>
    where
        F: Field + IntoShares<Replicated<F>>,
        Standard: Distribution<F>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [CappedCreditsWithAggregationBit<F>; 3] {
            let [a0, a1, a2] = self.0[0].share_with(rng);
            let [b0, b1, b2] = self.0[1].share_with(rng);
            let [c0, c1, c2] = self.0[2].share_with(rng);
            let [d0, d1, d2] = self.0[3].share_with(rng);
            [
                CappedCreditsWithAggregationBit {
                    helper_bit: a0,
                    breakdown_key: b0,
                    credit: c0,
                    aggregation_bit: d0,
                },
                CappedCreditsWithAggregationBit {
                    helper_bit: a1,
                    breakdown_key: b1,
                    credit: c1,
                    aggregation_bit: d1,
                },
                CappedCreditsWithAggregationBit {
                    helper_bit: a2,
                    breakdown_key: b2,
                    credit: c2,
                    aggregation_bit: d2,
                },
            ]
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [CappedCreditsWithAggregationBit<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            [&self[0], &self[1], &self[2]].reconstruct()
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [&CappedCreditsWithAggregationBit<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            let s0 = &self[0];
            let s1 = &self[1];
            let s2 = &self[2];

            let helper_bit = (&s0.helper_bit, &s1.helper_bit, &s2.helper_bit).reconstruct();

            let breakdown_key =
                (&s0.breakdown_key, &s1.breakdown_key, &s2.breakdown_key).reconstruct();
            let credit = (&s0.credit, &s1.credit, &s2.credit).reconstruct();

            let aggregation_bit = (
                &s0.aggregation_bit,
                &s1.aggregation_bit,
                &s2.aggregation_bit,
            )
                .reconstruct();

            AttributionTestInput([helper_bit, breakdown_key, credit, aggregation_bit])
        }
    }

    #[tokio::test]
    pub async fn aggregate() {
        const RAW_INPUT: &[[u128; 3]; 19] = &[
            // helper_bit, breakdown_key, credit
            [H[0], BD[3], 0],
            [H[0], BD[4], 0],
            [H[1], BD[4], 18],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[0], BD[1], 0],
            [H[0], BD[0], 0],
            [H[0], BD[2], 2],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[1], BD[2], 0],
            [H[1], BD[2], 10],
            [H[1], BD[0], 0],
            [H[1], BD[0], 0],
            [H[1], BD[5], 6],
            [H[1], BD[0], 0],
        ];
        const EXPECTED: &[[u128; 2]] = &[
            [0, 0],
            [1, 0],
            [2, 12],
            [3, 0],
            [4, 18],
            [5, 6],
            [6, 0],
            [7, 0],
        ];

        let input = RAW_INPUT.map(|x| {
            AttributionTestInput([
                Fp31::from(x[0]),
                Fp31::from(x[1]),
                Fp31::from(x[2]),
                Fp31::ZERO,
            ])
        });

        let world = TestWorld::new(QueryId);
        let result = world
            .semi_honest(input, |ctx, share| async move {
                aggregate_credit(ctx, &share, 8).await.unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(EXPECTED.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            // Each element in the `result` is a general purpose `[F; 4]`.
            // For this test case, the first two elements are `breakdown_key`
            // and `credit` as defined by the implementation of `Reconstruct`
            // for `[AggregateCreditOutputRow<F>; 3]`.
            let result = result[i].0.map(|x| x.as_u128());
            assert_eq!(*expected, [result[0], result[1]]);
        }
    }

    #[tokio::test]
    pub async fn sort() {
        // Result from CreditCapping, plus AggregateCredit pre-processing
        const RAW_INPUT: &[[u128; 4]; 27] = &[
            // helper_bit, breakdown_key, credit, aggregation_bit

            // AggregateCredit protocol inserts unique breakdown_keys with all
            // other fields with 0.
            [H[0], BD[0], 0, 0],
            [H[0], BD[1], 0, 0],
            [H[0], BD[2], 0, 0],
            [H[0], BD[3], 0, 0],
            [H[0], BD[4], 0, 0],
            [H[0], BD[5], 0, 0],
            [H[0], BD[6], 0, 0],
            [H[0], BD[7], 0, 0],
            // AggregateCredit protocol initializes helper_bits with 1 for all input rows.
            [H[1], BD[3], 0, 1],
            [H[1], BD[4], 0, 1],
            [H[1], BD[4], 18, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[1], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[2], 2, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[2], 0, 1],
            [H[1], BD[2], 10, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[5], 6, 1],
            [H[1], BD[0], 0, 1],
        ];

        // sorted by aggregation_bit, then by breakdown_key
        const EXPECTED: &[[u128; 4]; 27] = &[
            // breakdown_key 0
            [H[0], BD[0], 0, 0],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            [H[1], BD[0], 0, 1],
            // breakdown_key 1
            [H[0], BD[1], 0, 0],
            [H[1], BD[1], 0, 1],
            // breakdown_key 2
            [H[0], BD[2], 0, 0],
            [H[1], BD[2], 2, 1],
            [H[1], BD[2], 0, 1],
            [H[1], BD[2], 10, 1],
            // breakdown_key 3
            [H[0], BD[3], 0, 0],
            [H[1], BD[3], 0, 1],
            // breakdown_key 4
            [H[0], BD[4], 0, 0],
            [H[1], BD[4], 0, 1],
            [H[1], BD[4], 18, 1],
            // breakdown_key 5
            [H[0], BD[5], 0, 0],
            [H[1], BD[5], 6, 1],
            // breakdown_key 6
            [H[0], BD[6], 0, 0],
            // breakdown_key 7
            [H[0], BD[7], 0, 0],
        ];

        let input = RAW_INPUT.map(|x| {
            AttributionTestInput([
                Fp31::from(x[0]),
                Fp31::from(x[1]),
                Fp31::from(x[2]),
                Fp31::from(x[3]),
            ])
        });

        let world = TestWorld::new(QueryId);
        let result = world
            .semi_honest(input, |ctx, share| async move {
                sort_by_breakdown_key(ctx, &share, 8).await.unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(RAW_INPUT.len(), result.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(*expected, result[i].0.map(|x| x.as_u128()));
        }
    }
}
