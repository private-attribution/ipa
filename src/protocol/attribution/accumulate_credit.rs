use super::{
    compute_stop_bit, AccumulateCreditOutputRow, AttributionInputRow, InteractionPatternStep,
};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::attribution::AttributionResharableStep::{
    BreakdownKey, Credit, HelperBit, IsTriggerBit,
};
use crate::protocol::basics::SecureMul;
use crate::protocol::context::Context;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::sort::apply_sort::shuffle::Resharable;
use crate::protocol::RecordId;
use crate::secret_sharing::Replicated;
use async_trait::async_trait;
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

#[async_trait]
impl<F: Field> Resharable<F> for AttributionInputRow<F> {
    type Share = Replicated<F>;

    async fn reshare<C>(&self, ctx: C, record_id: RecordId, to_helper: Role) -> Result<Self, Error>
    where
        C: Context<F, Share = <Self as Resharable<F>>::Share> + Send,
    {
        let f_trigger_bit =
            ctx.narrow(&IsTriggerBit)
                .reshare(&self.is_trigger_bit, record_id, to_helper);
        let f_helper_bit = ctx
            .narrow(&HelperBit)
            .reshare(&self.helper_bit, record_id, to_helper);
        let f_breakdown_key =
            ctx.narrow(&BreakdownKey)
                .reshare(&self.breakdown_key, record_id, to_helper);
        let f_value = ctx
            .narrow(&Credit)
            .reshare(&self.credit, record_id, to_helper);

        let mut outputs =
            try_join_all([f_trigger_bit, f_helper_bit, f_breakdown_key, f_value]).await?;

        Ok(AttributionInputRow {
            is_trigger_bit: outputs.remove(0),
            helper_bit: outputs.remove(0),
            breakdown_key: outputs.remove(0),
            credit: outputs.remove(0),
        })
    }
}

/// The accumulation step operates on a sorted list with O(log N) iterations, where N is the input length.
/// It is the first step of the Oblivious Attribution protocol, and subsequent steps of all attribution models
/// (i.e., last touch, equal credit) use an output produced by this step. During each iteration, it accesses each
/// list element once, establishing a tree-like structure in which, starting from the leaf nodes, each node
/// accesses and accumulates data of its children. By increasing the distance between the interacting nodes during
/// each iteration by a factor of two, we ensure that each node only accumulates the value of each successor only once.
/// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
pub async fn accumulate_credit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[AttributionInputRow<F>],
) -> Result<Vec<AccumulateCreditOutputRow<F>>, Error> {
    let num_rows = input.len();

    // 1. Create stop_bit vector.
    // These vector is updated in each iteration to help accumulate values
    // and determine when to stop accumulating.

    let one = ctx.share_of_one();
    let mut stop_bits = repeat(one.clone()).take(num_rows).collect::<Vec<_>>();

    let mut credits = input.iter().map(|x| x.credit.clone()).collect::<Vec<_>>();

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
    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let mut futures = Vec::with_capacity(end);
        let c = ctx.narrow(&InteractionPatternStep::from(depth));

        for i in 0..end {
            let c = c.clone();
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_helper_bit = &input[i + step_size].helper_bit;
            let sibling_is_trigger_bit = &input[i + step_size].is_trigger_bit;
            let sibling_credit = &credits[i + step_size];
            futures.push(async move {
                // b = if [next event has the same match key]  AND
                //        [next event is a trigger event]      AND
                //        [accumulation has not completed yet]
                let b = compute_b_bit(
                    c.clone(),
                    record_id,
                    current_stop_bit,
                    sibling_helper_bit,
                    sibling_is_trigger_bit,
                    depth == 0,
                )
                .await?;

                try_join(
                    c.narrow(&Step::BTimesSuccessorCredit)
                        .multiply(record_id, &b, sibling_credit),
                    compute_stop_bit(
                        c.narrow(&Step::BTimesSuccessorStopBit),
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

        // accumulate the credit from this iteration into the accumulation vectors
        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                credits[i] = &credits[i] + &credit;
                stop_bits[i] = stop_bit;
            });
    }

    let output = input
        .iter()
        .enumerate()
        .map(|(i, x)| AccumulateCreditOutputRow {
            is_trigger_bit: x.is_trigger_bit.clone(),
            helper_bit: x.helper_bit.clone(),
            breakdown_key: x.breakdown_key.clone(),
            credit: credits[i].clone(),
        })
        .collect::<Vec<_>>();

    Ok(output)
}

async fn compute_b_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    current_stop_bit: &Replicated<F>,
    sibling_helper_bit: &Replicated<F>,
    sibling_is_trigger_bit: &Replicated<F>,
    first_iteration: bool,
) -> Result<Replicated<F>, Error> {
    // Compute `b = current_stop_bit * sibling_helper_bit * sibling_trigger_bit`.
    // Since `current_stop_bit` is initialized with 1, we only multiply it in
    // the second and later iterations.
    let mut b = ctx
        .narrow(&Step::HelperBitTimesIsTriggerBit)
        .multiply(record_id, sibling_helper_bit, sibling_is_trigger_bit)
        .await?;

    if !first_iteration {
        b = ctx
            .narrow(&Step::BTimesCurrentStopBit)
            .multiply(record_id, &b, current_stop_bit)
            .await?;
    }

    Ok(b)
}

#[cfg(all(test, not(feature = "shuttle")))]
pub(crate) mod tests {
    use rand::distributions::Standard;
    use rand::prelude::Distribution;

    use crate::protocol::sort::apply_sort::shuffle::Resharable;
    use crate::rand::{thread_rng, Rng};
    use crate::secret_sharing::IntoShares;
    use crate::secret_sharing::Replicated;
    use crate::{
        ff::{Field, Fp31},
        helpers::Role,
        protocol::attribution::{
            accumulate_credit::accumulate_credit,
            tests::{BD, H, S, T},
            AttributionInputRow,
        },
        protocol::{QueryId, RecordId},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct AttributionTestInput<F>(pub [F; 4]);

    impl<F> IntoShares<AttributionInputRow<F>> for AttributionTestInput<F>
    where
        F: Field + IntoShares<Replicated<F>>,
        Standard: Distribution<F>,
    {
        fn share_with<R: Rng>(self, rng: &mut R) -> [AttributionInputRow<F>; 3] {
            let [a0, a1, a2] = self.0[0].share_with(rng);
            let [b0, b1, b2] = self.0[1].share_with(rng);
            let [c0, c1, c2] = self.0[2].share_with(rng);
            let [d0, d1, d2] = self.0[3].share_with(rng);
            [
                AttributionInputRow {
                    is_trigger_bit: a0,
                    helper_bit: b0,
                    breakdown_key: c0,
                    credit: d0,
                },
                AttributionInputRow {
                    is_trigger_bit: a1,
                    helper_bit: b1,
                    breakdown_key: c1,
                    credit: d1,
                },
                AttributionInputRow {
                    is_trigger_bit: a2,
                    helper_bit: b2,
                    breakdown_key: c2,
                    credit: d2,
                },
            ]
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [AttributionInputRow<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            [&self[0], &self[1], &self[2]].reconstruct()
        }
    }

    impl<F: Field> Reconstruct<AttributionTestInput<F>> for [&AttributionInputRow<F>; 3] {
        fn reconstruct(&self) -> AttributionTestInput<F> {
            let s0 = &self[0];
            let s1 = &self[1];
            let s2 = &self[2];

            let is_trigger_bit =
                (&s0.is_trigger_bit, &s1.is_trigger_bit, &s2.is_trigger_bit).reconstruct();

            let helper_bit = (&s0.helper_bit, &s1.helper_bit, &s2.helper_bit).reconstruct();

            let breakdown_key =
                (&s0.breakdown_key, &s1.breakdown_key, &s2.breakdown_key).reconstruct();
            let credit = (&s0.credit, &s1.credit, &s2.credit).reconstruct();

            AttributionTestInput([is_trigger_bit, helper_bit, breakdown_key, credit])
        }
    }

    impl From<AttributionTestInput<Fp31>> for [u8; 4] {
        fn from(v: AttributionTestInput<Fp31>) -> Self {
            Self::from(&v)
        }
    }

    impl From<&AttributionTestInput<Fp31>> for [u8; 4] {
        fn from(v: &AttributionTestInput<Fp31>) -> Self {
            [
                u8::from(v.0[0]),
                u8::from(v.0[1]),
                u8::from(v.0[2]),
                u8::from(v.0[3]),
            ]
        }
    }
    #[tokio::test]
    pub async fn accumulate() {
        const TEST_CASE: &[[u128; 5]; 19] = &[
            // Each row array contains five elements. The first four elements
            // represents either a source or trigger event sent from a report
            // collector. Those four elements are:
            //
            // `is_trigger_bit`, `helper_bit`, `breakdown_key`, `credit`
            //
            // The last element in each row array represents a value expected
            // from running this protocol. For the `accumulation_credit`
            // protocol, they are the accumulated values using "last touch"
            // attribution model.

            // match key 1
            [S, H[0], BD[3], 0, 0],
            // match key 2
            [S, H[0], BD[4], 0, 0],
            [S, H[1], BD[4], 0, 19],
            [T, H[1], BD[0], 10, 19],
            [T, H[1], BD[0], 2, 9],
            [T, H[1], BD[0], 1, 7],
            [T, H[1], BD[0], 5, 6],
            [T, H[1], BD[0], 1, 1],
            // match key 3
            [S, H[0], BD[1], 0, 0],
            // match key 4
            [T, H[0], BD[0], 10, 10],
            // match key 5
            [S, H[0], BD[2], 0, 15],
            [T, H[1], BD[0], 3, 15],
            [T, H[1], BD[0], 12, 12],
            [S, H[1], BD[2], 0, 0],
            [S, H[1], BD[2], 0, 10],
            [T, H[1], BD[0], 6, 10],
            [T, H[1], BD[0], 4, 4],
            [S, H[1], BD[5], 0, 6],
            [T, H[1], BD[5], 6, 6],
        ];
        let expected = TEST_CASE.iter().map(|t| t[4]).collect::<Vec<_>>();

        let input = TEST_CASE.map(|x| {
            AttributionTestInput([
                Fp31::from(x[0]),
                Fp31::from(x[1]),
                Fp31::from(x[2]),
                Fp31::from(x[3]),
            ])
        });

        let world = TestWorld::new(QueryId);
        let result = world
            .semi_honest(input, |ctx, input| async move {
                accumulate_credit(ctx, &input).await.unwrap()
            })
            .await;

        assert_eq!(result[0].len(), TEST_CASE.len());
        assert_eq!(result[1].len(), TEST_CASE.len());
        assert_eq!(result[2].len(), TEST_CASE.len());

        for (i, expected) in expected.iter().enumerate() {
            let v = (
                &result[0][i].credit,
                &result[1][i].credit,
                &result[2][i].credit,
            )
                .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }

    #[tokio::test]
    pub async fn test_reshare() {
        let mut rng = thread_rng();
        let secret: [Fp31; 4] = [(); 4].map(|_| rng.gen::<Fp31>());

        let world = TestWorld::new(QueryId);

        for &role in Role::all() {
            let new_shares = world
                .semi_honest(
                    AttributionTestInput(secret),
                    |ctx, share: AttributionInputRow<Fp31>| async move {
                        share.reshare(ctx, RecordId::from(0), role).await.unwrap()
                    },
                )
                .await;
            assert_eq!(secret, new_shares.reconstruct().0);
        }
    }
}
