use super::{
    AccumulateCreditOutputRow, AttributionInputRow, InteractionPatternInputRow,
    InteractionPatternStep,
};

use crate::helpers::Role;
use crate::protocol::attribution::AttributionInputRowResharableStep::{
    BreakdownKey, Credit, HelperBit, IsTriggerBit,
};
use crate::protocol::context::SemiHonestContext;
use crate::protocol::mul::SecureMul;
use crate::protocol::sort::reshare_objects::Resharable;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        batch::{Batch, RecordIndex},
        context::Context,
        RecordId,
    },
    secret_sharing::Replicated,
};
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

    async fn resharable<C>(
        &self,
        ctx: C,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self, Error>
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
#[allow(dead_code)]
pub async fn accumulate_credit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &Batch<AttributionInputRow<F>>,
) -> Result<Batch<AccumulateCreditOutputRow<F>>, Error> {
    let num_rows: RecordIndex = input.len().try_into().unwrap();

    // 1. Create stop_bit vector.
    // These vector is updated in each iteration to help accumulate values
    // and determine when to stop accumulating.

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
                interaction_value: credits[i].clone(),
            };
            let successor = InteractionPatternInputRow {
                is_trigger_bit: input[i + step_size].is_trigger_bit.clone(),
                helper_bit: input[i + step_size].helper_bit.clone(),
                stop_bit: stop_bits[i + step_size].clone(),
                interaction_value: credits[i + step_size].clone(),
            };

            accumulation_futures.push(accumulate_credit_interaction_pattern(
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
            is_trigger_bit: x.is_trigger_bit.clone(),
            helper_bit: x.helper_bit.clone(),
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

async fn accumulate_credit_interaction_pattern<F: Field>(
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
        &successor.interaction_value,
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        helpers::Role,
        protocol::{
            attribution::accumulate_credit::accumulate_credit, attribution::AttributionInputRow,
            batch::Batch, sort::reshare_objects::Resharable, QueryId, RecordId,
        },
        test_fixture::{share, Reconstruct, Runner, TestWorld},
    };
    use rand::{rngs::mock::StepRng, Rng};
    use std::iter::zip;
    use tokio::try_join;

    const S: u128 = 0;
    const T: u128 = 1;
    const H: [u128; 2] = [0, 1];
    const BD: [u128; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

    /// Takes a vector of 4-element vectors (e.g., `RAW_INPUT`), and create
    /// shares of `AttributionInputRow`.
    // TODO(taikiy): Implement a `IntoShares` for any struct
    fn generate_shared_input(
        input: &[[u128; 5]],
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

        let world = TestWorld::<Fp31>::new(QueryId);
        let context = world.contexts();
        let mut rng = StepRng::new(100, 1);

        let shares = generate_shared_input(TEST_CASE, &mut rng);

        let [c0, c1, c2] = context;
        let [s0, s1, s2] = shares;

        let h0_future = accumulate_credit(c0, &s0);
        let h1_future = accumulate_credit(c1, &s1);
        let h2_future = accumulate_credit(c2, &s2);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), TEST_CASE.len());
        assert_eq!(result.1.len(), TEST_CASE.len());
        assert_eq!(result.2.len(), TEST_CASE.len());

        for (i, expected) in expected.iter().enumerate() {
            let v = (
                &result.0[i].credit,
                &result.1[i].credit,
                &result.2[i].credit,
            )
                .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }

    #[tokio::test]
    pub async fn test_resharable() {
        let mut rng = rand::thread_rng();
        let secret: [Fp31; 4] = [(); 4].map(|_| rng.gen::<Fp31>());

        let world = TestWorld::<Fp31>::new(QueryId);

        for &role in Role::all() {
            let new_shares = world
                .semi_honest(secret, |ctx, share: AttributionInputRow<Fp31>| async move {
                    share
                        .resharable(ctx, RecordId::from(0), role)
                        .await
                        .unwrap()
                })
                .await;
            assert_eq!(secret, new_shares.reconstruct());
        }
    }
}
