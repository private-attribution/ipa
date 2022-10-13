use super::{AccumulationInputRow, AccumulationOutputRow, AttributionInputRow};
use crate::{
    error::BoxError,
    field::Field,
    helpers::{fabric::Network, prss::SpaceIndex},
    protocol::{
        batch::{Batch, RecordIndex},
        context::ProtocolContext,
        RecordId, Step,
    },
    secret_sharing::Replicated,
};
use futures::future::{try_join, try_join_all};

/// Accumulation step for Oblivious Attribution protocol.
#[allow(dead_code)]
pub struct Accumulate<'a, F> {
    input: &'a Batch<AttributionInputRow<F>>,
}

impl<'a, F: Field> Accumulate<'a, F> {
    #[allow(dead_code)]
    pub fn new(input: &'a Batch<AttributionInputRow<F>>) -> Self {
        Self { input }
    }

    /// The accumulation step operates on a sorted list with O(log N) iterations, where N is the input length.
    /// It is the first step of the Oblivious Attribution protocol, and subsequent steps of all attribution models
    /// (i.e., last touch, equal credit) use an output produced by this step. During each iteration, it accesses each
    /// list element once, establishing a tree-like structure in which, starting from the leaf nodes, each node
    /// accesses and accumulates data of its children. By increasing the distance between the interacting nodes during
    /// each iteration by a factor of two, we ensure that each node only accumulates the value of each successor only once.
    /// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
    #[allow(dead_code)]
    pub async fn execute<S, N>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        steps: [S; 5],
    ) -> Result<Batch<AccumulationOutputRow<F>>, BoxError>
    where
        S: Step + SpaceIndex,
        N: Network<S>,
    {
        //
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = self.input.len() as RecordIndex;

        // 1. Create credit and stop_bit vectors
        // These vectors are updated in each iteration to help accumulate values and determine when to stop accumulating.

        let one = Replicated::one(ctx.gateway.get_channel(steps[0]).identity());
        let mut stop_bits: Batch<Replicated<F>> = vec![one; num_rows as usize].into();

        let mut credits: Batch<Replicated<F>> = self
            .input
            .iter()
            .map(|x| x.value)
            .collect::<Vec<_>>()
            .into();

        // 2. Accumulate (up to 4 multiplications)
        //
        // For each iteration (`step_size`), we access each node in the list to accumulate values. The accumulation can
        // be optimized to the following arithmetic circuit.
        //
        //     b = current.stop_bit * successor.helper_bit * successor.trigger_bit;
        //     new_credit[current_index] = current.credit + b * successor.credit;
        //     new_stop_bit[current_index] = b * successor.stop_bit;
        //
        // Each list element interacts with exactly one other element in each iteration, and the interaction do not
        // depend on the calculation results other elements, allowing the algorithm to be executed in parallel.

        // generate powers of 2 that fit into input len. If num_rows is 15, this will produce [1, 2, 4, 8]
        for step_size in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
        {
            let end = num_rows - step_size;
            let mut accumulation_futures = Vec::with_capacity(end as usize);

            // for each input row, create a future to execute secure multiplications
            for i in 0..end {
                let current = AccumulationInputRow {
                    stop_bit: stop_bits[i],
                    credit: credits[i],
                    report: self.input[i],
                };
                let successor = AccumulationInputRow {
                    stop_bit: stop_bits[i + step_size],
                    credit: credits[i + step_size],
                    report: self.input[i + step_size],
                };

                accumulation_futures.push(self.get_accumulated_credit(
                    ctx,
                    step_size,
                    current,
                    successor,
                    RecordId::from(i),
                    [steps[1], steps[2], steps[3], steps[4]],
                ));
            }

            let results = try_join_all(accumulation_futures).await?;

            // save the calculation results to these support vectors for use in the next iteration
            results
                .into_iter()
                .enumerate()
                .for_each(|(i, (credit, stop_bit))| {
                    credits[i] += credit;
                    stop_bits[i] = stop_bit;
                });
        }

        // drop irrelevant fields and add another supporting field called `aggregation_bit` for the next step
        let output: Batch<AccumulationOutputRow<F>> = self
            .input
            .iter()
            .enumerate()
            .map(|(i, x)| AccumulationOutputRow {
                breakdown_key: x.breakdown_key,
                credit: credits[i],
                aggregation_bit: one,
            })
            .collect::<Vec<_>>()
            .into();

        // TODO: Append unique breakdown_key values at the end of the output vector for the next step
        // Since we cannot see the actual breakdown key values, we'll append shares of [0..MAX]. Adding u8::MAX
        // number of elements to the output won't be a problem. Adding u32::MAX elements will be 1B + u32::MAX, which
        // exceeds our current assumption of `input.len() < 1B`.

        Ok(output)
    }

    async fn get_accumulated_credit<S, N>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        step_size: u32,
        current: AccumulationInputRow<F>,
        successor: AccumulationInputRow<F>,
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

#[cfg(test)]
mod tests {
    use crate::{
        field::{Field, Fp31},
        helpers::prss::SpaceIndex,
        protocol::{attribution::accumulate::Accumulate, batch::Batch, Step},
        protocol::{attribution::AttributionInputRow, QueryId},
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    enum AccumulateTestStep {
        Step(usize),
    }

    impl Step for AccumulateTestStep {}

    impl SpaceIndex for AccumulateTestStep {
        const MAX: usize = 5;
        fn as_usize(&self) -> usize {
            match self {
                AccumulateTestStep::Step(i) => *i,
            }
        }
    }

    fn generate_shared_input(
        input: &[[u128; 4]],
        rng: &mut StepRng,
    ) -> [Batch<AttributionInputRow<Fp31>>; 3] {
        let num_rows = input.len();
        let mut shares = [
            Batch::from(Vec::with_capacity(num_rows)),
            Batch::from(Vec::with_capacity(num_rows)),
            Batch::from(Vec::with_capacity(num_rows)),
        ];

        for x in input {
            let (h0, (h1, h2)): (Vec<_>, (Vec<_>, Vec<_>)) = x
                .iter()
                .map(|y| {
                    let ss = share(Fp31::from(*y), rng);
                    (ss[0], (ss[1], ss[2]))
                })
                .unzip();
            shares[0].push(AttributionInputRow {
                is_trigger_bit: h0[0],
                helper_bit: h0[1],
                breakdown_key: h0[2],
                value: h0[3],
            });
            shares[1].push(AttributionInputRow {
                is_trigger_bit: h1[0],
                helper_bit: h1[1],
                breakdown_key: h1[2],
                value: h1[3],
            });
            shares[2].push(AttributionInputRow {
                is_trigger_bit: h2[0],
                helper_bit: h2[1],
                breakdown_key: h2[2],
                value: h2[3],
            });
        }

        assert_eq!(shares[0].len(), shares[1].len());
        assert_eq!(shares[1].len(), shares[2].len());

        shares
    }

    #[tokio::test]
    pub async fn accumulate() {
        let world: TestWorld<AccumulateTestStep> = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = StepRng::new(100, 1);

        let raw_input: [[u128; 4]; 9] = [
            // [is_trigger, helper_bit, breakdown_key, credit]
            [0, 0, 3, 0],
            [0, 1, 4, 0],
            [1, 1, 0, 10],
            [1, 1, 0, 2],
            [1, 1, 0, 1],
            [1, 1, 0, 5],
            [1, 1, 0, 1],
            [0, 0, 1, 0],
            [1, 0, 0, 10],
        ];

        let shares = generate_shared_input(&raw_input, &mut rng);

        // Attribution Step (last touch):
        // Iter 0             [0,  0, 10, 2, 1, 5, 1, 0, 10]
        // Stop bits           -  --  --  -  -  -  -  -  --
        // Iter 1 (step = 1)  [0, 10, 12, 3, 6, 6, 1, 0, 10]
        // Stop bits              --  --  -  -  -
        // Iter 2 (step = 2)  [0, 13, 18, 9, 7, 6, 1, 0, 10]
        // Stop bits              --  --  -
        // Iter 3 (step = 4)  [0, 19, 19, 9, 7, 6, 1, 0, 10]
        // Stop bits
        // Iter 4 (step = 8)  [0, 19, 19, 9, 7, 6, 1, 0, 10]

        let expected_credit_output = vec![0_u128, 19, 19, 9, 7, 6, 1, 0, 10];

        let steps = [
            AccumulateTestStep::Step(0),
            AccumulateTestStep::Step(1),
            AccumulateTestStep::Step(2),
            AccumulateTestStep::Step(3),
            AccumulateTestStep::Step(4),
        ];

        let acc0 = Accumulate::new(&shares[0]);
        let acc1 = Accumulate::new(&shares[1]);
        let acc2 = Accumulate::new(&shares[2]);
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
