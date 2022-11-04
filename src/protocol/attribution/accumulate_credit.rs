use super::{AccumulateCreditInputRow, AccumulateCreditOutputRow, AttributionInputRow, IterStep};
use crate::{
    error::BoxError,
    ff::Field,
    protocol::{
        batch::{Batch, RecordIndex},
        context::ProtocolContext,
        RecordId,
    },
    secret_sharing::Replicated,
};
use futures::future::{try_join, try_join_all};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    HelperBitTimesIsTriggerBit,
    BTimesStopBit,
    BTimesSuccessorCredit,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::HelperBitTimesIsTriggerBit => "helper_bit_times_is_trigger_bit",
            Self::BTimesStopBit => "b_times_stop_bit",
            Self::BTimesSuccessorCredit => "b_times_successor_credit",
        }
    }
}

/// Accumulation step for Oblivious Attribution protocol.
#[allow(dead_code)]
pub struct AccumulateCredit<'a, F> {
    input: &'a Batch<AttributionInputRow<F>>,
}

impl<'a, F: Field> AccumulateCredit<'a, F> {
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
    pub async fn execute(
        &self,
        ctx: ProtocolContext<'_, F>,
    ) -> Result<Batch<AccumulateCreditOutputRow<F>>, BoxError> {
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = self.input.len() as RecordIndex;

        // 1. Create credit and stop_bit vectors
        // These vectors are updated in each iteration to help accumulate values and determine when to stop accumulating.

        let one = Replicated::one(ctx.role());
        let mut stop_bits: Batch<Replicated<F>> = vec![one; num_rows as usize].try_into().unwrap();

        let mut credits: Batch<Replicated<F>> = self
            .input
            .iter()
            .map(|x| x.value)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // 2. Accumulate (up to 4 multiplications)
        //
        // For each iteration (`log2(input.len())`), we access each node in the
        // list to accumulate values. The accumulation can be optimized to the
        // following arithmetic circuit.
        //
        //   b = current.stop_bit * successor.helper_bit * successor.trigger_bit;
        //   new_credit[current_index] = current.credit + b * successor.credit;
        //   new_stop_bit[current_index] = b * successor.stop_bit;
        //
        // Each list element interacts with exactly one other element in each
        // iteration, and the interaction do not depend on the calculation results
        // of other elements, allowing the algorithm to be executed in parallel.

        let mut iteration_step = IterStep::new("iteration");

        // generate powers of 2 that fit into input len. If num_rows is 15, this will produce [1, 2, 4, 8]
        for step_size in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
        {
            let end = num_rows - step_size;
            let mut accumulation_futures = Vec::with_capacity(end as usize);

            let ctx = ctx.narrow(iteration_step.next());
            let mut multiply_step = IterStep::new("multiply");

            // for each input row, create a future to execute secure multiplications
            for i in 0..end {
                let current = AccumulateCreditInputRow {
                    stop_bit: stop_bits[i],
                    credit: credits[i],
                    report: self.input[i],
                };
                let successor = AccumulateCreditInputRow {
                    stop_bit: stop_bits[i + step_size],
                    credit: credits[i + step_size],
                    report: self.input[i + step_size],
                };

                accumulation_futures.push(Self::get_accumulated_credit(
                    ctx.narrow(multiply_step.next()),
                    RecordId::from(i),
                    current,
                    successor,
                    iteration_step.is_first_iteration(),
                ));
            }

            let results = try_join_all(accumulation_futures).await?;

            // accumulate the credit from this iteration into the accumulation vectors
            results
                .into_iter()
                .enumerate()
                .for_each(|(i, (credit, stop_bit))| {
                    credits[i] += credit;
                    stop_bits[i] = stop_bit;
                });
        }

        // drop irrelevant fields and add another supporting field called `aggregation_bit` for the next step
        let output: Batch<AccumulateCreditOutputRow<F>> = self
            .input
            .iter()
            .enumerate()
            .map(|(i, x)| AccumulateCreditOutputRow {
                breakdown_key: x.breakdown_key,
                credit: credits[i],
                aggregation_bit: one,
            })
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        // TODO: Append unique breakdown_key values at the end of the output vector for the next step
        // Since we cannot see the actual breakdown key values, we'll append shares of [0..MAX]. Adding u8::MAX
        // number of elements to the output won't be a problem. Adding u32::MAX elements will be 1B + u32::MAX, which
        // exceeds our current assumption of `input.len() < 1B`.

        Ok(output)
    }

    async fn get_accumulated_credit(
        ctx: ProtocolContext<'_, F>,
        record_id: RecordId,
        current: AccumulateCreditInputRow<F>,
        successor: AccumulateCreditInputRow<F>,
        first_iteration: bool,
    ) -> Result<(Replicated<F>, Replicated<F>), BoxError> {
        // For each input row, we execute the accumulation logic in this method
        // `log2(input.len())` times. Each accumulation logic is executed with
        // the unique iteration/row pair sub-context. There are 2~4 multiplications
        // in this accumulation logic, and each is tagged with a unique `RecordID`.

        // first, calculate [successor.helper_bit * successor.trigger_bit]
        let mut b = ctx
            .narrow(&Step::HelperBitTimesIsTriggerBit)
            .multiply(record_id)
            .execute(successor.report.helper_bit, successor.report.is_trigger_bit)
            .await?;

        // since `stop_bits` is initialized with `[1]`s, we only multiply `stop_bit` in the second and later iterations
        if !first_iteration {
            b = ctx
                .narrow(&Step::BTimesStopBit)
                .multiply(RecordId::from(1_u32))
                .execute(b, current.stop_bit)
                .await?;
        }

        let credit_future = ctx
            .narrow(&Step::BTimesSuccessorCredit)
            .multiply(record_id)
            .execute(b, successor.credit);

        // for the same reason as calculating [b], we skip the multiplication in the first iteration
        let stop_bit_future = if first_iteration {
            futures::future::Either::Left(futures::future::ok(b))
        } else {
            futures::future::Either::Right(ctx.multiply(record_id).execute(b, successor.stop_bit))
        };

        try_join(credit_future, stop_bit_future).await
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        ff::{Field, Fp31},
        protocol::{attribution::accumulate_credit::AccumulateCredit, batch::Batch},
        protocol::{attribution::AttributionInputRow, QueryId},
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct},
    };
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    fn generate_shared_input(
        input: &[[u128; 4]],
        rng: &mut StepRng,
    ) -> [Batch<AttributionInputRow<Fp31>>; 3] {
        let num_rows = input.len();
        let mut shares = [
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
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

        [
            Batch::try_from(shares[0].clone()).unwrap(),
            Batch::try_from(shares[1].clone()).unwrap(),
            Batch::try_from(shares[2].clone()).unwrap(),
        ]
    }

    #[tokio::test]
    pub async fn accumulate() {
        let world = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
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

        // Accumulation Step (last touch):
        // Iter 0 credits          [0,  0, 10,  2,  1,  5,  1,  0, 10]
        // Stop bits               [1,  1,  1,  1,  1 , 1,  1,  1,  1]
        // Iter 1 (step_size = 1)  [0, 10, 12,  3,  6,  6,  1,  0, 10]
        // Stop bits               [0,  1,  1,  1,  1,  1,  0,  0,  0]
        // Iter 2 (step_size = 2)  [0, 13, 18,  9,  7,  6,  1,  0, 10]
        // Stop bits               [0,  1,  1,  1,  0,  0,  0,  0,  0]
        // Iter 3 (step_size = 4)  [0, 19, 19,  9,  7,  6,  1,  0, 10]
        // Stop bits               [0,  0,  0,  0,  0,  0,  0,  0,  0]
        // Iter 4 (step_size = 8)  [0, 19, 19,  9,  7,  6,  1,  0, 10]

        let expected_credit_output = vec![0_u128, 19, 19, 9, 7, 6, 1, 0, 10];

        let acc0 = AccumulateCredit::new(&shares[0]);
        let acc1 = AccumulateCredit::new(&shares[1]);
        let acc2 = AccumulateCredit::new(&shares[2]);

        let [c0, c1, c2] = context;
        let h0_future = acc0.execute(c0);
        let h1_future = acc1.execute(c1);
        let h2_future = acc2.execute(c2);

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
