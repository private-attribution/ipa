use super::{AggregateCreditInputRow, AggregateCreditOutputRow, CreditCappingOutputRow};
use crate::{
    error::Error,
    ff::Field,
    protocol::{
        batch::{Batch, RecordIndex},
        context::SemiHonestContext,
        RecordId, Substep,
    },
    secret_sharing::Replicated,
};
use futures::future::{try_join, try_join_all};

/// Aggregation step for Oblivious Attribution protocol.
pub struct AggregateCredit {}

impl AggregateCredit {
    /// Aggregation step uses the same tree-like structure approach as we did in `Accumulate` step.
    /// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        input: &Batch<CreditCappingOutputRow<F>>,
    ) -> Result<Batch<CreditCappingOutputRow<F>>, Error> {
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = input.len() as RecordIndex;

        //
        // Step 1. Add aggregation bits and append unique breakdown_key
        // values at the end of the input list.
        //
        let zero = Replicated::new(F::ZERO, F::ZERO);
        let one = Replicated::one(ctx.role());
        let mut batch = input
            .iter()
            .map(|x| AggregateCreditInputRow {
                helper_bit: one,
                stop_bit: one,
                aggregation_bit: one,
                breakdown_key: x.breakdown_key,
                credit: x.credit,
            })
            .collect::<Vec<_>>();

        // Since we cannot see the actual breakdown key values, we'll append shares of
        // (0..=F::MAX). Adding u8::MAX won't be a problem, but u32::MAX will be >1B.
        (0..=F::MAX.as_u128()).for_each(|i| {
            batch.push(AggregateCreditInputRow {
                helper_bit: zero,
                stop_bit: one,
                aggregation_bit: zero,
                breakdown_key: one * F::from(i),
                credit: zero,
            })
        });

        //
        // 2. TODO: Send to the sort protocol
        //

        //
        // 3. Aggregate
        //     b = current.stop_bit * successor.helper_bit * successor.trigger_bit;
        //     new_credit[current_index] = current.credit + b * successor.credit;
        //     new_stop_bit[current_index] = b * successor.stop_bit;
        //
        let mut iteration_step = IterStep::new("aggregate_iteration", 0);
        for step_size in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
        {
            let end = num_rows - step_size;
            let mut interaction_futures = Vec::with_capacity(end as usize);

            for i in 0..end {
                let current = InteractionPatternInputRow {
                    is_trigger_bit: zero.clone(),
                    stop_bit: stop_bits[i],
                    credit: credits[i],
                    report: self.input[i],
                };
                let successor = InteractionPatternInputRow {
                    is_trigger_bit: zero.clone(),
                    stop_bit: stop_bits[i + step_size],
                    credit: credits[i + step_size],
                    report: self.input[i + step_size],
                };

                // accumulation_futures.push(self.get_accumulated_credit(
                //     ctx,
                //     step_size,
                //     current,
                //     successor,
                //     RecordId::from(i),
                //     [steps[1], steps[2], steps[3], steps[4]],
                // ));
            }

            // let results = try_join_all(accumulation_futures).await?;

            // save the calculation results to these support vectors for use in the next iteration
            // results
            //     .into_iter()
            //     .enumerate()
            //     .for_each(|(i, (credit, stop_bit))| {
            //         credits[i] += credit;
            //         stop_bits[i] = stop_bit;
            //     });
        }

        let output: Batch<_> = input
            .iter()
            .enumerate()
            .map(|(i, x)| AggregateCreditOutputRow {
                breakdown_key: x.breakdown_key,
                credit: x.credit,
            })
            .collect::<Vec<_>>()
            .into();

        Ok(output)
    }

    async fn get_accumulated_credit<S, N>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        step_size: u32,
        current: AccumulateCreditInputRow<F>,
        successor: AccumulateCreditInputRow<F>,
        record_id: RecordId,
        steps: [S; 4],
    ) -> Result<(Replicated<F>, Replicated<F>), BoxError>
    where
        S: Step + SpaceIndex,
        N: Network<S>,
    {
        // first, calculate [successor.helper_bit * successor.trigger_bit]
        let mut b = ctx
            .multiply(record_id, steps[0])
            .await
            .execute(successor.report.helper_bit, successor.report.is_trigger_bit)
            .await?;

        // since `stop_bits` is initialized with `[1]`s, we only multiply `stop_bit` in the second and later iterations
        if step_size > 1 {
            b = ctx
                .multiply(record_id, steps[1])
                .await
                .execute(b, current.stop_bit)
                .await?;
        }

        let credit_future = ctx
            .multiply(record_id, steps[2])
            .await
            .execute(b, successor.credit);

        // for the same reason as calculating [b], we skip the multiplication in the first iteration
        let stop_bit_future = if step_size > 1 {
            futures::future::Either::Left(
                ctx.multiply(record_id, steps[3])
                    .await
                    .execute(b, successor.stop_bit),
            )
        } else {
            futures::future::Either::Right(futures::future::ok(b))
        };

        try_join(credit_future, stop_bit_future).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BTimesStopBit,
    BTimesSuccessorStopBit,
    MaskSourceCredits,
    CurrentContributionBTimesSuccessorCredit,
    BitDecomposeCurrentContribution,
    IsCapLessThanCurrentContribution,
    FinalCreditsSourceContribution,
    FinalCreditsNextContribution,
    FinalCreditsCompareBitTimesBudget,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BTimesStopBit => "b_times_stop_bit",
            Self::BTimesSuccessorStopBit => "b_times_successor_stop_bit",
            Self::MaskSourceCredits => "mask_source_credits",
            Self::CurrentContributionBTimesSuccessorCredit => {
                "current_contribution_b_times_successor_credit"
            }
            Self::BitDecomposeCurrentContribution => "bit_decompose_current_contribution",
            Self::IsCapLessThanCurrentContribution => "is_cap_less_than_current_contribution",
            Self::FinalCreditsSourceContribution => "final_credits_source_contribution",
            Self::FinalCreditsNextContribution => "final_credits_next_contribution",
            Self::FinalCreditsCompareBitTimesBudget => "final_credits_compare_bit_times_budget",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        field::{Field, Fp31},
        helpers::prss::SpaceIndex,
        protocol::{attribution::accumulate_credit::AccumulateCredit, batch::Batch, Step},
        protocol::{attribution::AttributionInputRow, QueryId},
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng};
    use std::iter::zip;
    use tokio::try_join;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum AggregateTestStep {
        Step(usize),
    }

    impl Step for AggregateTestStep {}

    impl SpaceIndex for AggregateTestStep {
        const MAX: usize = 5;
        fn as_usize(&self) -> usize {
            match self {
                AggregateTestStep::Step(i) => *i,
            }
        }
    }

    fn generate_shared_input<F: Field>(
        input: &[[u128; 4]],
        rng: &mut StepRng,
    ) -> [Batch<AttributionInputRow<F>>; 3]
    where
        Standard: Distribution<F>,
    {
        let num_rows = input.len();
        let mut shares = [
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
        ];

        for x in input {
            let s = x
                .iter()
                .map(|y| share(F::from(*y), rng))
                .collect::<Vec<_>>();

            for (i, r) in s.enumerate() {
                shares[i].push(AttributionInputRow { is_trigger_bit: r })
            }
            // shares[0].push(AttributionInputRow {
            //     is_trigger_bit: h0[0],
            //     helper_bit: h0[1],
            //     breakdown_key: h0[2],
            //     value: h0[3],
            // });
            // shares[1].push(AttributionInputRow {
            //     is_trigger_bit: h1[0],
            //     helper_bit: h1[1],
            //     breakdown_key: h1[2],
            //     value: h1[3],
            // });
            // shares[2].push(AttributionInputRow {
            //     is_trigger_bit: h2[0],
            //     helper_bit: h2[1],
            //     breakdown_key: h2[2],
            //     value: h2[3],
            // });
        }

        assert_eq!(shares[0].len(), shares[1].len());
        assert_eq!(shares[1].len(), shares[2].len());

        [
            Batch::from(shares[0].clone()),
            Batch::from(shares[1].clone()),
            Batch::from(shares[2].clone()),
        ]
    }

    #[tokio::test]
    pub async fn aggregate() {
        let world: TestWorld<AggregateTestStep> = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = StepRng::new(100, 1);

        let raw_input: [[u128; 4]; 13] = [
            // [helper_bit, breakdown_key, credit, aggregation_bit]
            [0, 1, 0, 0],
            [1, 1, 0, 0],
            [1, 2, 0, 10],
            [0, 2, 0, 2],
            [1, 3, 0, 1],
            [0, 3, 0, 5],
            [1, 4, 0, 1],
            [0, 4, 0, 0],
            [0, 0, 0, 10],
            [0, 0, 0, 10],
            [0, 0, 0, 10],
            [0, 0, 0, 10],
            [0, 0, 0, 10],
        ];

        let shares = generate_shared_input(&raw_input, &mut rng);

        // Accumulation Step (last touch):
        // Iter 0                  [0,  0, 10,  2,  1,  5,  1,  0, 10]
        // Stop bits               [1,  1,  1,  1,  1 , 1,  1,  1,  1]
        // Iter 1 (step_size = 1)  [0, 10, 12,  3,  6,  6,  1,  0, 10]
        // Stop bits               [0,  1,  1,  1,  1,  1,  0,  0,  0]
        // Iter 2 (step_size = 2)  [0, 13, 18,  9,  7,  6,  1,  0, 10]
        // Stop bits               [0,  1,  1,  1,  0,  0,  0,  0,  0]
        // Iter 3 (step_size = 4)  [0, 19, 19,  9,  7,  6,  1,  0, 10]
        // Stop bits               [0,  0,  0,  0,  0,  0,  0,  0,  0]
        // Iter 4 (step_size = 8)  [0, 19, 19,  9,  7,  6,  1,  0, 10]

        let expected_credit_output = vec![0_u128, 19, 19, 9, 7, 6, 1, 0, 10];

        let steps = (0..=4)
            .map(AggregateTestStep::Step)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let acc0 = AccumulateCredit::new(&shares[0]);
        let acc1 = AccumulateCredit::new(&shares[1]);
        let acc2 = AccumulateCredit::new(&shares[2]);
        let h0_future = acc0.execute(&context[0], steps);
        let h1_future = acc1.execute(&context[1], steps);
        let h2_future = acc2.execute(&context[2], steps);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), raw_input.len());
        assert_eq!(result.1.len(), raw_input.len());
        assert_eq!(result.2.len(), raw_input.len());

        (0..(result.0.len())).for_each(|i| {
            let v = validate_and_reconstruct((
                result.0[i].credit,
                result.1[i].credit,
                result.2[i].credit,
            ));
            assert_eq!(v.as_u128(), expected_credit_output[i]);
        });
    }
}
