use super::input::{MCAccumulateCreditInputRow, MCAccumulateCreditOutputRow};
use super::{compute_stop_bit, InteractionPatternStep};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::basics::SecureMul;
use crate::protocol::context::Context;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::RecordId;
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
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

/// The accumulation step operates on a sorted list with O(log N) iterations, where N is the input length.
/// It is the first step of the Oblivious Attribution protocol, and subsequent steps of all attribution models
/// (i.e., last touch, equal credit) use an output produced by this step. During each iteration, it accesses each
/// list element once, establishing a tree-like structure in which, starting from the leaf nodes, each node
/// accesses and accumulates data of its children. By increasing the distance between the interacting nodes during
/// each iteration by a factor of two, we ensure that each node only accumulates the value of each successor only once.
/// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
pub async fn accumulate_credit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[MCAccumulateCreditInputRow<F>],
) -> Result<Vec<MCAccumulateCreditOutputRow<F>>, Error> {
    let num_rows = input.len();
    let ctx = ctx.set_total_records(num_rows);

    // 1. Create stop_bit vector.
    // These vector is updated in each iteration to help accumulate values
    // and determine when to stop accumulating.

    let one = ctx.share_of_one();
    let mut stop_bits = repeat(one.clone()).take(num_rows).collect::<Vec<_>>();

    let mut credits = input
        .iter()
        .map(|x| x.trigger_value.clone())
        .collect::<Vec<_>>();

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
            let sibling_is_trigger_bit = &input[i + step_size].is_trigger_report;
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
        .map(|(i, x)| MCAccumulateCreditOutputRow {
            is_trigger_report: x.is_trigger_report.clone(),
            helper_bit: x.helper_bit.clone(),
            breakdown_key: x.breakdown_key.clone(),
            trigger_value: credits[i].clone(),
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
mod tests {
    use crate::accumulation_test_input;
    use crate::ff::{Field, Fp31, Fp32BitPrime};
    use crate::helpers::Role;
    use crate::protocol::attribution::input::MCAccumulateCreditOutputRow;
    use crate::protocol::attribution::{
        accumulate_credit::accumulate_credit,
        input::{AccumulateCreditInputRow, MCAccumulateCreditInputRow},
    };
    use crate::protocol::modulus_conversion::{
        combine_slices, convert_all_bits, convert_all_bits_local,
    };
    use crate::protocol::sort::apply_sort::shuffle::Resharable;
    use crate::protocol::{context::Context, RecordId};
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::rand::thread_rng;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use rand::Rng;

    const NUM_MULTI_BITS: u32 = 3;

    #[tokio::test]
    pub async fn accumulate() {
        const EXPECTED: &[u128; 19] = &[
            0, 0, 19, 19, 9, 7, 6, 1, 0, 10, 15, 15, 12, 0, 10, 10, 4, 6, 6,
        ];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 3, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 5, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 6 }
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let world = TestWorld::new().await;
        let result: [Vec<MCAccumulateCreditOutputRow<Fp32BitPrime>>; 3] = world
            .semi_honest(
                input,
                |ctx, input: Vec<AccumulateCreditInputRow<Fp32BitPrime, BreakdownKey>>| async move {
                    let bk_shares = input
                        .iter()
                        .map(|x| x.breakdown_key.clone())
                        .collect::<Vec<_>>();
                    let converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), &bk_shares),
                        BreakdownKey::BITS,
                        NUM_MULTI_BITS,
                    )
                    .await
                    .unwrap();
                    let converted_bk_shares =
                        combine_slices(&converted_bk_shares, BreakdownKey::BITS);
                    let modulus_converted_shares = input
                        .into_iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCAccumulateCreditInputRow {
                            is_trigger_report: row.is_trigger_report,
                            breakdown_key: bk,
                            trigger_value: row.trigger_value,
                            helper_bit: row.helper_bit,
                        })
                        .collect::<Vec<_>>();

                    accumulate_credit(ctx, &modulus_converted_shares)
                        .await
                        .unwrap()
                },
            )
            .await;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);
        assert_eq!(result[0].len(), EXPECTED.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = [
                &result[0][i].trigger_value,
                &result[1][i].trigger_value,
                &result[2][i].trigger_value,
            ]
            .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }

    #[tokio::test]
    pub async fn test_reshare() {
        let mut rng = thread_rng();
        let secret: GenericReportTestInput<Fp31, MatchKey, BreakdownKey> =
            accumulation_test_input!(
                [{
                    is_trigger_report: rng.gen::<u8>(),
                    helper_bit: rng.gen::<u8>(),
                    breakdown_key: rng.gen::<u8>(),
                    credit: rng.gen::<u8>()
                }];
                (Fp31, MathKey, BreakdownKey)
            )
            .remove(0);

        let world = TestWorld::new().await;
        for &role in Role::all() {
            let new_shares = world
                .semi_honest(
                    secret,
                    |ctx, share: AccumulateCreditInputRow<Fp31, BreakdownKey>| async move {
                        let bk_shares = vec![share.breakdown_key];
                        let converted_bk_shares = convert_all_bits(
                            &ctx,
                            &convert_all_bits_local(ctx.role(), &bk_shares),
                            BreakdownKey::BITS,
                            NUM_MULTI_BITS,
                        )
                        .await
                        .unwrap();
                        let mut converted_bk_shares =
                            combine_slices(&converted_bk_shares, BreakdownKey::BITS);
                        let modulus_converted_share = MCAccumulateCreditInputRow {
                            is_trigger_report: share.is_trigger_report,
                            breakdown_key: converted_bk_shares.next().unwrap(),
                            trigger_value: share.trigger_value,
                            helper_bit: share.helper_bit,
                        };

                        modulus_converted_share
                            .reshare(ctx.set_total_records(1), RecordId::from(0), role)
                            .await
                            .unwrap()
                    },
                )
                .await;
            assert_eq!(secret, new_shares.reconstruct());
        }
    }
}
