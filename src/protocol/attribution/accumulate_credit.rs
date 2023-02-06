use super::input::{MCAccumulateCreditInputRow, MCAccumulateCreditOutputRow};
use super::InteractionPatternStep;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::Arithmetic;
use futures::future::{try_join, try_join_all};
use std::marker::PhantomData;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    MemoizeIsTriggerBitTimesHelperBit,
    BTimesSuccessorCredit,
    BTimesSuccessorStopBit,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MemoizeIsTriggerBitTimesHelperBit => "memoize_is_trigger_bit_times_helper_bit",
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
pub async fn accumulate_credit<F, C, T>(
    ctx: C,
    input: &[MCAccumulateCreditInputRow<F, T>],
) -> Result<Vec<MCAccumulateCreditOutputRow<F, T>>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    let num_rows = input.len();

    // For every row, compute:
    // input[i].is_triger_bit * input[i].helper_bit
    // Save this value as it will be used on every iteration.
    // We can skip the very first row, since there is no row above that will check it as a "sibling"
    let memoize_context = ctx
        .narrow(&Step::MemoizeIsTriggerBitTimesHelperBit)
        .set_total_records(num_rows - 1);
    let helper_bits =
        try_join_all(input.iter().skip(1).enumerate().map(|(i, x)| {
            let c = memoize_context.clone();
            let record_id = RecordId::from(i);
            let is_trigger_bit = &x.is_trigger_report;
            let helper_bit = &x.helper_bit;
            async move { c.multiply(record_id, is_trigger_bit, helper_bit).await }
        }))
        .await?;

    // For the very first iteration:
    // credit[i] = input[i].trigger_value + input[i+1].is_trigger_bit * input[i+1].helper_bit * input[i+1].trigger_value
    let depth_0_ctx = ctx
        .narrow(&Step::BTimesSuccessorCredit)
        .set_total_records(num_rows - 1);
    let credit_updates = try_join_all(
        input
            .iter()
            .skip(1)
            .zip(helper_bits.iter())
            .enumerate()
            .map(|(i, (x, b))| {
                let c = depth_0_ctx.clone();
                let record_id = RecordId::from(i);
                async move { c.multiply(record_id, b, &x.trigger_value).await }
            }),
    )
    .await?;

    let mut credits = input
        .iter()
        .zip(credit_updates)
        .map(|(x, update)| update + &x.trigger_value)
        .collect::<Vec<_>>();
    credits.push(input.last().unwrap().trigger_value.clone());

    // Create stop_bit vector.
    // These vector is updated in each iteration to help accumulate values
    // and determine when to stop accumulating.
    let mut stop_bits = helper_bits.clone();
    stop_bits.push(ctx.share_known_value(F::ONE));

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
    for (depth, step_size) in std::iter::successors(Some(2_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let depth_i_ctx = ctx
            .narrow(&InteractionPatternStep::from(depth + 1))
            .set_total_records(end);
        let b_times_sibling_credit_ctx = depth_i_ctx.narrow(&Step::BTimesSuccessorCredit);
        let b_times_sibling_stop_bit_ctx = depth_i_ctx.narrow(&Step::BTimesSuccessorStopBit);
        let mut futures = Vec::with_capacity(end);
        
        for i in 0..end {
            let c1 = depth_i_ctx.clone();
            let c2 = b_times_sibling_credit_ctx.clone();
            let c3 = b_times_sibling_stop_bit_ctx.clone();
            let record_id = RecordId::from(i);
            let sibling_helper_bit = &helper_bits[i + step_size - 1];
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_credit = &credits[i + step_size];
            futures.push(async move {
                let b = c1
                    .multiply(record_id, current_stop_bit, sibling_helper_bit)
                    .await?;

                try_join(
                    c2.multiply(record_id, &b, sibling_credit),
                    c3.multiply(record_id, &b, sibling_stop_bit),
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

    let output = input
        .iter()
        .enumerate()
        .map(|(i, x)| MCAccumulateCreditOutputRow {
            is_trigger_report: x.is_trigger_report.clone(),
            helper_bit: x.helper_bit.clone(),
            breakdown_key: x.breakdown_key.clone(),
            trigger_value: credits[i].clone(),
            _marker: PhantomData::default(),
        })
        .collect::<Vec<_>>();

    Ok(output)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::marker::PhantomData;

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
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
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
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let world = TestWorld::new().await;
        let result: [Vec<MCAccumulateCreditOutputRow<Fp32BitPrime, Replicated<Fp32BitPrime>>>; 3] = world
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
                            _marker: PhantomData::default(),
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
        let secret: GenericReportTestInput<Fp31, MatchKey, BreakdownKey> = accumulation_test_input!(
            {
                is_trigger_report: rng.gen::<u8>(),
                helper_bit: rng.gen::<u8>(),
                breakdown_key: rng.gen::<u8>(),
                credit: rng.gen::<u8>(),
            };
            (Fp31, MathKey, BreakdownKey)
        );

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
                            _marker: PhantomData::default(),
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
