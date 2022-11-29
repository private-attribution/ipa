use super::{
    AccumulateCreditOutputRow, AttributionInputRow, InteractionPatternInputRow,
    InteractionPatternStep,
};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::batch::{Batch, RecordIndex};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::mul::SecureMul;
use crate::protocol::RecordId;
use crate::secret_sharing::Replicated;
use futures::future::{try_join, try_join_all};
use std::iter::repeat;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    HelperBitTimesIsTriggerBit,
    BTimesCurrentStopBit,
    BTimesSuccessorCredit,
    BTimesSuccessorStopBit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::HelperBitTimesIsTriggerBit => "helper_bit_times_is_trigger_bit",
            Self::BTimesCurrentStopBit => "b_times_current_stop_bit",
            Self::BTimesSuccessorCredit => "b_times_successor_credit",
            Self::BTimesSuccessorStopBit => "b_times_successor_stop_bit",
        }
    }
}

/// Accumulation step for Oblivious Attribution protocol.
#[allow(dead_code)]
pub struct AccumulateCredit {}

impl AccumulateCredit {
    /// The accumulation step operates on a sorted list with O(log N) iterations, where N is the input length.
    /// It is the first step of the Oblivious Attribution protocol, and subsequent steps of all attribution models
    /// (i.e., last touch, equal credit) use an output produced by this step. During each iteration, it accesses each
    /// list element once, establishing a tree-like structure in which, starting from the leaf nodes, each node
    /// accesses and accumulates data of its children. By increasing the distance between the interacting nodes during
    /// each iteration by a factor of two, we ensure that each node only accumulates the value of each successor only once.
    /// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        input: &Batch<AttributionInputRow<F>>,
    ) -> Result<Batch<AccumulateCreditOutputRow<F>>, Error> {
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = input.len() as RecordIndex;

        // 1. Create `stop_bit` vector
        // This vector is updated in each iteration to help accumulate values and determine when to stop accumulating.

        let one = Replicated::one(ctx.role());
        let mut stop_bits: Batch<Replicated<F>> = repeat(one.clone())
            .take(usize::try_from(num_rows).unwrap())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let mut credits: Batch<Replicated<F>> = input
            .iter()
            .map(|x| x.credit.clone())
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

        // generate powers of 2 that fit into input len. If num_rows is 15, this will produce [1, 2, 4, 8]
        for (depth, step_size) in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
            .enumerate()
        {
            let end = num_rows - step_size;
            let mut accumulation_futures = Vec::with_capacity(end as usize);

            let c = ctx.narrow(&InteractionPatternStep::Depth(depth));

            // for each input row, create a future to execute secure multiplications
            for i in 0..end {
                // TODO - see if making so many copies can be reduced
                let current = InteractionPatternInputRow {
                    is_trigger_bit: input[i].is_trigger_bit.clone(),
                    helper_bit: input[i].helper_bit.clone(),
                    stop_bit: stop_bits[i].clone(),
                    interaction_bit: credits[i].clone(),
                };
                let successor = InteractionPatternInputRow {
                    is_trigger_bit: input[i + step_size].is_trigger_bit.clone(),
                    helper_bit: input[i + step_size].helper_bit.clone(),
                    stop_bit: stop_bits[i + step_size].clone(),
                    interaction_bit: credits[i + step_size].clone(),
                };

                accumulation_futures.push(Self::get_accumulated_credit(
                    c.clone(),
                    RecordId::from(i),
                    current,
                    successor,
                    depth == 0,
                ));
            }

            let results = try_join_all(accumulation_futures).await?;

            // accumulate the credit from this iteration into the accumulation vectors
            results
                .into_iter()
                .enumerate()
                .for_each(|(i, (credit, stop_bit))| {
                    credits[i] = &credits[i] + &credit;
                    stop_bits[i] = stop_bit;
                });
        }

        let output: Batch<AccumulateCreditOutputRow<F>> = input
            .iter()
            .enumerate()
            .map(|(i, x)| AccumulateCreditOutputRow {
                is_trigger_bit: input[i].is_trigger_bit.clone(),
                helper_bit: input[i].helper_bit.clone(),
                breakdown_key: x.breakdown_key.clone(),
                credit: credits[i].clone(),
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

    async fn get_accumulated_credit<F: Field>(
        ctx: SemiHonestContext<'_, F>,
        record_id: RecordId,
        current: InteractionPatternInputRow<F>,
        successor: InteractionPatternInputRow<F>,
        first_iteration: bool,
    ) -> Result<(Replicated<F>, Replicated<F>), Error> {
        // For each input row, we execute the accumulation logic in this method
        // `log2(input.len())` times. Each accumulation logic is executed with
        // the unique iteration/row pair sub-context. There are 2~4 multiplications
        // in this accumulation logic, and each is tagged with a unique `RecordID`.

        // first, calculate [successor.helper_bit * successor.trigger_bit]
        let mut b = ctx
            .narrow(&Step::HelperBitTimesIsTriggerBit)
            .multiply(record_id, &successor.helper_bit, &successor.is_trigger_bit)
            .await?;

        // since `stop_bits` is initialized with `[1]`s, we only multiply `stop_bit` in the second and later iterations
        if !first_iteration {
            b = ctx
                .narrow(&Step::BTimesCurrentStopBit)
                .multiply(record_id, &b, &current.stop_bit)
                .await?;
        }

        let credit_future = ctx.narrow(&Step::BTimesSuccessorCredit).multiply(
            record_id,
            &b,
            &successor.interaction_bit,
        );

        // for the same reason as calculating [b], we skip the multiplication in the first iteration
        let stop_bit_future = if first_iteration {
            futures::future::Either::Left(futures::future::ok(b.clone()))
        } else {
            futures::future::Either::Right(ctx.narrow(&Step::BTimesSuccessorStopBit).multiply(
                record_id,
                &b,
                &successor.stop_bit,
            ))
        };

        try_join(credit_future, stop_bit_future).await
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        protocol::{attribution::accumulate_credit::AccumulateCredit, batch::Batch},
        protocol::{attribution::AttributionInputRow, QueryId},
        test_fixture::{share, Reconstruct, TestWorld},
    };
    use rand::rngs::mock::StepRng;
    use std::iter::zip;
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
            let itb = share(Fp31::from(x[0]), rng);
            let hb = share(Fp31::from(x[1]), rng);
            let bk = share(Fp31::from(x[2]), rng);
            let val = share(Fp31::from(x[3]), rng);
            for (i, ((itb, hb), (bk, val))) in zip(zip(itb, hb), zip(bk, val)).enumerate() {
                shares[i].push(AttributionInputRow {
                    is_trigger_bit: itb,
                    helper_bit: hb,
                    breakdown_key: bk,
                    credit: val,
                });
            }
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
        const RAW_INPUT: &[[u128; 4]; 19] = &[
            // [is_trigger, helper_bit, breakdown_key, credit]
            [0, 0, 3, 0],
            [0, 0, 4, 0],
            [0, 1, 4, 0],
            [1, 1, 0, 10],
            [1, 1, 0, 2],
            [1, 1, 0, 1],
            [1, 1, 0, 5],
            [1, 1, 0, 1],
            [0, 0, 1, 0],
            [1, 0, 0, 10],
            [0, 0, 2, 0],
            [1, 1, 0, 3],
            [1, 1, 0, 12],
            [0, 1, 2, 0],
            [0, 1, 2, 0],
            [1, 1, 0, 6],
            [1, 1, 0, 4],
            [0, 1, 5, 0],
            [1, 1, 5, 6],
        ];
        const EXPECTED: &[u128] = &[
            0, 0, 19, 19, 9, 7, 6, 1, 0, 10, 15, 15, 12, 0, 10, 10, 4, 6, 6,
        ];

        let world = TestWorld::<Fp31>::new(QueryId);
        let context = world.contexts();
        let mut rng = StepRng::new(100, 1);

        let shares = generate_shared_input(RAW_INPUT, &mut rng);

        let [c0, c1, c2] = context;
        let [s0, s1, s2] = shares;

        let h0_future = AccumulateCredit::execute(c0, &s0);
        let h1_future = AccumulateCredit::execute(c1, &s1);
        let h2_future = AccumulateCredit::execute(c2, &s2);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), RAW_INPUT.len());
        assert_eq!(result.1.len(), RAW_INPUT.len());
        assert_eq!(result.2.len(), RAW_INPUT.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = (
                &result.0[i].credit,
                &result.1[i].credit,
                &result.2[i].credit,
            )
                .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }
}
