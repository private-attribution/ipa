use super::input::{MCApplyAttributionWindowInputRow, MCApplyAttributionWindowOutputRow};
use super::InteractionPatternStep;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::boolean::random_bits_generator::RandomBitsGenerator;
use crate::protocol::boolean::{bitwise_greater_than_constant, BitDecomposition};
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::Arithmetic;
use futures::future::{try_join, try_join_all};
use std::iter::{repeat, zip};

/// This protocol applies the specified attribution window to trigger events. All trigger values of
/// events that are outside the window will be replaced with 0, hence will not be attributed to
/// corresponding source events in the later aggregation stages.
///
/// # Errors
/// Fails if sub-protocols fails.
#[allow(dead_code)]
async fn apply_attribution_window<F, C, T>(
    ctx: C,
    input: &[MCApplyAttributionWindowInputRow<F, T>],
    attribution_window_seconds: u32,
) -> Result<Vec<MCApplyAttributionWindowOutputRow<F, T>>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    let t_deltas = prefix_sum_time_deltas(&ctx, input).await?;

    let trigger_values =
        zero_out_expired_trigger_values(&ctx, input, &t_deltas, attribution_window_seconds).await?;

    Ok(input
        .iter()
        .zip(trigger_values)
        .map(|(x, value)| {
            MCApplyAttributionWindowOutputRow::new(
                x.is_trigger_report.clone(),
                x.helper_bit.clone(),
                x.breakdown_key.clone(),
                value,
            )
        })
        .collect::<Vec<_>>())
}

/// Computes time deltas from each trigger event to its nearest matching source event.
///
/// # Errors
/// Fails if the multiplication fails.
async fn prefix_sum_time_deltas<F, C, T>(
    ctx: &C,
    input: &[MCApplyAttributionWindowInputRow<F, T>],
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    let num_rows = input.len();

    // Pre-compute `is_trigger_bit * helper_bit'.
    // Later in the prefix-sum loop, this vector is updated in each iteration to help
    // accumulate timedeltas and determine when to stop accumulating.
    let stop_bit_context = ctx
        .narrow(&Step::IsTriggerBitTimesHelperBit)
        .set_total_records(num_rows - 1);
    let mut stop_bits = Some(T::ZERO)
        .into_iter()
        .chain(
            try_join_all(input.iter().skip(1).enumerate().map(|(i, x)| {
                let c = stop_bit_context.clone();
                let record_id = RecordId::from(i);
                async move {
                    c.multiply(record_id, &x.is_trigger_report, &x.helper_bit)
                        .await
                }
            }))
            .await?,
        )
        .collect::<Vec<_>>();

    // First, create a vector of timedeltas. This vector contains non-zero values only for
    // rows with `stop_bit` = 1, meaning that the row is a trigger event, and has the same
    // match key as the event one above.
    let t_delta_context = ctx
        .narrow(&Step::InitializeTimeDelta)
        .set_total_records(num_rows - 1);
    let mut t_delta = Some(T::ZERO)
        .into_iter()
        .chain(
            try_join_all(
                zip(input.iter(), input.iter().skip(1))
                    .zip(stop_bits.iter().skip(1))
                    .enumerate()
                    .map(|(i, ((prev, curr), b))| {
                        let c = t_delta_context.clone();
                        let record_id = RecordId::from(i);
                        let delta = curr.timestamp.clone() - &prev.timestamp;
                        async move { c.multiply(record_id, &delta, b).await }
                    }),
            )
            .await?,
        )
        .collect::<Vec<_>>();

    // Do the prefix-sum accumulation of timedeltas. This is similar to
    // `do_the_binary_tree_thing()`, but it sums up values in top-down order.
    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let record_count = num_rows - step_size;

        let depth_i_ctx = ctx
            .narrow(&InteractionPatternStep::from(depth))
            .set_total_records(record_count);
        let mt_ctx = depth_i_ctx.narrow(&Step::PreviousStopBitTimesCurrent);

        let mut futures = Vec::with_capacity(record_count);

        // `i` starts from 0 for RecordId. The actual logic skips the first
        // `step_size` rows.
        for i in 0..record_count {
            let index = i + step_size;

            let c1 = depth_i_ctx.clone();
            let c2 = mt_ctx.clone();
            let record_id = RecordId::from(i);

            let previous_stop_bit = &stop_bits[index - step_size];
            let current_stop_bit = &stop_bits[index];
            let previous_t_delta = &t_delta[index - step_size];

            futures.push(async move {
                try_join(
                    // if the current stop_bit is 0, don't accumulate
                    c1.multiply(record_id, previous_t_delta, current_stop_bit),
                    // next `stop_bit`
                    c2.multiply(record_id, previous_stop_bit, current_stop_bit),
                )
                .await
            });
        }

        let results = try_join_all(futures).await?;

        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (delta, stop_bit))| {
                t_delta[i + step_size] += &delta;
                stop_bits[i + step_size] = stop_bit;
            });
    }

    Ok(t_delta)
}

/// Creates a vector of trigger values where values are set to `0` if the time delta
/// from their nearest source event exceed the specified attribution window cap.
///
/// This protocol executes the bit-decomposition protocol in order to compare shares
/// of time deltas in `F`.
///
/// # Errors
/// Fails if the bit-decomposition, bitwise comparison, or multiplication fails.
async fn zero_out_expired_trigger_values<F, C, T>(
    ctx: &C,
    input: &[MCApplyAttributionWindowInputRow<F, T>],
    time_delta: &[T],
    cap: u32,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    // Compare the accumulated timestamp deltas with the specified attribution window
    // cap value, and zero-out trigger event values that exceed the cap.
    let c = ctx.clone().set_total_records(input.len());
    let bit_decomposition_ctx = c.narrow(&Step::TimeDeltaBitDecomposition);
    let cmp_ctx = c.narrow(&Step::TimeDeltaLessThanCap);
    let mul_ctx = c.narrow(&Step::CompareBitTimesTriggerValue);

    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForBitDecomposition));
    let rbg = &random_bits_generator;

    try_join_all(
        zip(input, time_delta)
            .zip(repeat(ctx.share_known_value(F::ONE)))
            .enumerate()
            .map(|(i, ((row, delta), one))| {
                let c1 = bit_decomposition_ctx.clone();
                let c2 = cmp_ctx.clone();
                let c3 = mul_ctx.clone();
                let record_id = RecordId::from(i);

                async move {
                    let delta_bits = BitDecomposition::execute(c1, record_id, rbg, delta).await?;
                    let compare_bit = one
                        - &bitwise_greater_than_constant(c2, record_id, &delta_bits, cap.into())
                            .await?;
                    c3.multiply(record_id, &row.trigger_value, &compare_bit)
                        .await
                }
            }),
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    IsTriggerBitTimesHelperBit,
    InitializeTimeDelta,
    PreviousStopBitTimesCurrent,
    RandomBitsForBitDecomposition,
    TimeDeltaBitDecomposition,
    TimeDeltaLessThanCap,
    CompareBitTimesTriggerValue,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::IsTriggerBitTimesHelperBit => "is_trigger_bit_times_helper_bit",
            Self::InitializeTimeDelta => "initialize_time_delta",
            Self::PreviousStopBitTimesCurrent => "previous_stop_bit_times_current",
            Self::RandomBitsForBitDecomposition => "random_bits_for_bit_decomposition",
            Self::TimeDeltaBitDecomposition => "time_delta_bit_decomposition",
            Self::TimeDeltaLessThanCap => "time_delta_less_than_cap",
            Self::CompareBitTimesTriggerValue => "compare_bit_times_trigger_value",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::attribution_window_test_input;
    use crate::ff::{Field, Fp32BitPrime};
    use crate::protocol::attribution::{
        apply_attribution_window::apply_attribution_window,
        input::{
            ApplyAttributionWindowInputRow, MCApplyAttributionWindowInputRow,
            MCApplyAttributionWindowOutputRow,
        },
    };
    use crate::protocol::context::Context;
    use crate::protocol::modulus_conversion::{convert_all_bits, convert_all_bits_local};
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};

    #[tokio::test]
    pub async fn attribution_window() {
        const ATTRIBUTION_WINDOW: u32 = 600;
        const EXPECTED: &[u128; 23] = &[
            0, 0, 0, 10, 2, 1, 5, 1, 0, 0, 0, 10, 0, 3, 12, 0, 0, 6, 4, 0, 6, 1, 0,
        ];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = attribution_window_test_input!(
            [
                { timestamp: 500, is_trigger_report: 0, helper_bit: 0, breakdown_key: 3, credit: 0 }, // delta: 0
                { timestamp: 100, is_trigger_report: 0, helper_bit: 0, breakdown_key: 4, credit: 0 }, // delta: 0
                { timestamp: 130, is_trigger_report: 0, helper_bit: 1, breakdown_key: 4, credit: 0 }, // delta: 0
                { timestamp: 150, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 10 },// delta: 20
                { timestamp: 250, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 }, // delta: 120
                { timestamp: 310, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 }, // delta: 180
                { timestamp: 420, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 5 }, // delta: 290
                { timestamp: 540, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 }, // delta: 410
                { timestamp: 890, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 3 }, // delta: 760
                { timestamp: 920, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 5 }, // delta: 790
                { timestamp: 110, is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 0 }, // delta: 0
                { timestamp: 310, is_trigger_report: 1, helper_bit: 0, breakdown_key: 0, credit: 10 },// delta: 0
                { timestamp: 270, is_trigger_report: 0, helper_bit: 0, breakdown_key: 2, credit: 0 }, // delta: 0
                { timestamp: 390, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 3 }, // delta: 120
                { timestamp: 420, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 12 },// delta: 150
                { timestamp: 530, is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 }, // delta: 0
                { timestamp: 790, is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 }, // delta: 0
                { timestamp: 990, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 6 }, // delta: 200
                { timestamp: 1100, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 4 },// delta: 310
                { timestamp: 1200, is_trigger_report: 0, helper_bit: 1, breakdown_key: 5, credit: 0 },// delta: 0
                { timestamp: 1490, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 6 },// delta: 290
                { timestamp: 1800, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 1 },// delta: 600
                { timestamp: 1960, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 3 },// delta: 760
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let world = TestWorld::new().await;
        let result: [Vec<MCApplyAttributionWindowOutputRow<Fp32BitPrime, Replicated<Fp32BitPrime>>>; 3] = world
            .semi_honest(
                input,
                |ctx, input: Vec<ApplyAttributionWindowInputRow<Fp32BitPrime, BreakdownKey>>| async move {
                    let bk_shares = input
                        .iter()
                        .map(|x| x.breakdown_key.clone())
                        .collect::<Vec<_>>();
                    let mut converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), &bk_shares),
                        BreakdownKey::BITS,
                        BreakdownKey::BITS,
                    )
                        .await
                        .unwrap();
                    let converted_bk_shares =
                    converted_bk_shares.pop().unwrap();
                    let modulus_converted_shares = input
                        .into_iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCApplyAttributionWindowInputRow::new(
                            row.timestamp,
                            row.is_trigger_report,
                            row.helper_bit,
                            bk,
                            row.trigger_value,
                        ))
                        .collect::<Vec<_>>();

                    apply_attribution_window(ctx, &modulus_converted_shares, ATTRIBUTION_WINDOW)
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
}
