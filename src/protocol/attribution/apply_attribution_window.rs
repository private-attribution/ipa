use super::{
    do_the_binary_tree_thing,
    input::{MCApplyAttributionWindowInputRow, MCApplyAttributionWindowOutputRow},
};
use crate::{
    error::Error,
    ff::{Field, PrimeField},
    protocol::{
        boolean::{greater_than_constant, random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};
use ipa_macros::step;
use std::{
    iter::{repeat, zip},
    num::NonZeroU32,
};
use strum::AsRefStr;

/// This protocol applies the specified attribution window to trigger events. All trigger values of
/// events that are outside the window will be replaced with 0, hence will not be attributed to
/// corresponding source events in the later aggregation stages.
///
/// # Errors
/// Fails if sub-protocols fails.
#[tracing::instrument(name = "apply_window", skip_all)]
pub async fn apply_attribution_window<C, S, F>(
    ctx: C,
    input: &[MCApplyAttributionWindowInputRow<F, S>],
    stop_bits: &[S],
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<MCApplyAttributionWindowOutputRow<F, S>>, Error>
where
    C: Context + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F> + 'static,
    F: PrimeField,
{
    if let Some(attribution_window_seconds) = attribution_window_seconds {
        let mut t_deltas = prefix_sum_time_deltas(&ctx, input, stop_bits).await?;

        let result = zero_out_expired_trigger_values(
            &ctx,
            input,
            &mut t_deltas,
            attribution_window_seconds.get(),
        )
        .await?;

        Ok(input
            .iter()
            .zip(result)
            .map(|(x, (active_bit, value))| {
                MCApplyAttributionWindowOutputRow::new(
                    x.is_trigger_report.clone(),
                    x.helper_bit.clone(),
                    active_bit,
                    x.breakdown_key.clone(),
                    value,
                )
            })
            .collect::<Vec<_>>())
    } else {
        // attribution window is not set, skip the entire protocol
        Ok(input
            .iter()
            .map(|x| {
                MCApplyAttributionWindowOutputRow::new(
                    x.is_trigger_report.clone(),
                    x.helper_bit.clone(),
                    S::ZERO,
                    x.breakdown_key.clone(),
                    x.trigger_value.clone(),
                )
            })
            .collect::<Vec<_>>())
    }
}

/// Computes time deltas from each trigger event to its nearest matching source event.
///
/// # Errors
/// Fails if the multiplication fails.
async fn prefix_sum_time_deltas<F, C, T>(
    ctx: &C,
    input: &[MCApplyAttributionWindowInputRow<F, T>],
    stop_bits: &[T],
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let num_rows = input.len();

    // First, create a vector of timedeltas. This vector contains non-zero values only for
    // rows with `stop_bit` = 1, meaning that the row is a trigger event, and has the same
    // match key as the event one above.
    let t_delta_context = ctx
        .narrow(&Step::InitializeTimeDelta)
        .set_total_records(num_rows - 1);
    let mut t_delta = std::iter::once(T::ZERO)
        .chain(
            ctx.try_join(
                zip(input.iter(), input.iter().skip(1))
                    .zip(stop_bits)
                    .enumerate()
                    .map(|(i, ((prev, curr), b))| {
                        let c = t_delta_context.clone();
                        let record_id = RecordId::from(i);
                        let delta = curr.timestamp.clone() - &prev.timestamp;
                        async move { delta.multiply(b, c, record_id).await }
                    }),
            )
            .await?,
        )
        .rev()
        .collect::<Vec<_>>();

    // TODO: Change the input/output to iterators
    do_the_binary_tree_thing(
        ctx.clone(),
        stop_bits.iter().rev().cloned().collect(),
        &mut t_delta,
    )
    .await?;
    t_delta.reverse();

    Ok(t_delta)
}

/// Creates a vector of tuples. The right elements are trigger values where values are
/// set to `0` if the time delta from their nearest source event exceed the specified
/// attribution window cap. Each of the left elements is a share of {0, 1} indicating
/// whether the corresponding credit is valid (1) or has been zero'ed-out (0).
///
/// This protocol executes the bit-decomposition protocol in order to compare shares
/// of time deltas in `F`.
///
/// # Errors
/// Fails if the bit-decomposition, bitwise comparison, or multiplication fails.
async fn zero_out_expired_trigger_values<F, C, T>(
    ctx: &C,
    input: &[MCApplyAttributionWindowInputRow<F, T>],
    time_delta: &mut [T],
    cap: u32,
) -> Result<Vec<(T, T)>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let ctx = ctx.set_total_records(input.len());
    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForBitDecomposition));
    let rbg = &random_bits_generator;
    let cmp_ctx = ctx.narrow(&Step::TimeDeltaLessThanCap);
    let mul_ctx = ctx.narrow(&Step::CompareBitTimesTriggerValue);

    // Compare the accumulated timestamp deltas with the specified attribution window
    // cap value, and zero-out trigger event values that exceed the cap.
    ctx.try_join(
        zip(input, time_delta)
            .zip(repeat(T::share_known_value(&ctx, F::ONE)))
            .enumerate()
            .map(|(i, ((row, delta), one))| {
                let c1 = cmp_ctx.clone();
                let c2 = mul_ctx.clone();
                let record_id = RecordId::from(i);

                async move {
                    let compare_bit =
                        one - &greater_than_constant(c1, record_id, rbg, delta, cap.into()).await?;
                    let new_value = row
                        .trigger_value
                        .multiply(&compare_bit, c2, record_id)
                        .await?;
                    Ok((compare_bit, new_value))
                }
            }),
    )
    .await
}

#[step]
pub(crate) enum Step {
    InitializeTimeDelta,
    RandomBitsForBitDecomposition,
    TimeDeltaLessThanCap,
    CompareBitTimesTriggerValue,
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        attribution_window_test_input,
        ff::{Field, Fp32BitPrime},
        protocol::{
            attribution::{
                apply_attribution_window::apply_attribution_window,
                compute_stop_bits,
                input::{
                    ApplyAttributionWindowInputRow, MCApplyAttributionWindowInputRow,
                    MCApplyAttributionWindowOutputRow,
                },
            },
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };
    use std::{iter::zip, num::NonZeroU32};

    #[tokio::test]
    pub async fn attribution_window() {
        const EXPECTED_TRIGGER_VALUES: &[u128; 23] = &[
            0, 0, 0, 10, 2, 1, 5, 1, 0, 0, 0, 10, 0, 3, 12, 0, 0, 6, 4, 0, 6, 1, 0,
        ];
        const EXPECTED_ACTIVE_BITS: &[u128; 23] = &[
            1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
        ];
        const ATTRIBUTION_WINDOW: Option<NonZeroU32> = NonZeroU32::new(600);
        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = attribution_window_test_input!(
            [
                { timestamp: 500, is_trigger_report: 0, helper_bit: 0, breakdown_key: 3, credit: 0 }, // delta: 0
                { timestamp: 100, is_trigger_report: 0, helper_bit: 0, breakdown_key: 4, credit: 0 }, // delta: 0 reset
                { timestamp: 130, is_trigger_report: 0, helper_bit: 1, breakdown_key: 4, credit: 0 }, // delta: 0 reset
                { timestamp: 150, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 10 },// delta: 20
                { timestamp: 250, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 }, // delta: 120
                { timestamp: 310, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 }, // delta: 180
                { timestamp: 420, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 5 }, // delta: 290
                { timestamp: 540, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 }, // delta: 410
                { timestamp: 890, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 3 }, // delta: 760
                { timestamp: 920, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 5 }, // delta: 790
                { timestamp: 110, is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 0 }, // delta: 0 reset
                { timestamp: 310, is_trigger_report: 1, helper_bit: 0, breakdown_key: 0, credit: 10 },// delta: n/a
                { timestamp: 270, is_trigger_report: 0, helper_bit: 0, breakdown_key: 2, credit: 0 }, // delta: 0 reset
                { timestamp: 390, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 3 }, // delta: 120
                { timestamp: 420, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 12 },// delta: 150
                { timestamp: 530, is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 }, // delta: 0 reset
                { timestamp: 790, is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 }, // delta: 0 reset
                { timestamp: 990, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 6 }, // delta: 200
                { timestamp: 1100, is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 4 },// delta: 310
                { timestamp: 1200, is_trigger_report: 0, helper_bit: 1, breakdown_key: 5, credit: 0 },// delta: 0 reset
                { timestamp: 1490, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 6 },// delta: 290
                { timestamp: 1800, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 1 },// delta: 600
                { timestamp: 1960, is_trigger_report: 1, helper_bit: 1, breakdown_key: 5, credit: 3 },// delta: 760
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let world = TestWorld::default();
        let result: [Vec<MCApplyAttributionWindowOutputRow<Fp32BitPrime, Replicated<Fp32BitPrime>>>; 3] = world
            .semi_honest(
                input.into_iter(),
                |ctx, input: Vec<ApplyAttributionWindowInputRow<Fp32BitPrime, BreakdownKey>>| async move {
                    let bk_shares = input
                        .iter()
                        .map(|x| x.breakdown_key.clone());
                    let mut converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), bk_shares),
                        BreakdownKey::BITS,
                        BreakdownKey::BITS,
                    )
                        .await
                        .unwrap();
                    let converted_bk_shares =
                    converted_bk_shares.pop().unwrap();
                    let modulus_converted_shares = input
                        .iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCApplyAttributionWindowInputRow::new(
                            row.timestamp.clone(),
                            row.is_trigger_report.clone(),
                            row.helper_bit.clone(),
                            bk,
                            row.trigger_value.clone(),
                        ))
                        .collect::<Vec<_>>();

                    let (itb, hb): (Vec<_>, Vec<_>) = input.iter().map(|x| (x.is_trigger_report.clone(), x.helper_bit.clone())).unzip();
                    let stop_bits = compute_stop_bits(ctx.clone(), &itb, &hb).await.unwrap().collect::<Vec<_>>();

                    apply_attribution_window(ctx, &modulus_converted_shares, &stop_bits, ATTRIBUTION_WINDOW)
                        .await
                        .unwrap()
                },
            )
            .await;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);
        assert_eq!(result[0].len(), EXPECTED_TRIGGER_VALUES.len());

        for (i, (value, active_bit)) in
            zip(EXPECTED_TRIGGER_VALUES, EXPECTED_ACTIVE_BITS).enumerate()
        {
            let v = [
                &result[0][i].trigger_value,
                &result[1][i].trigger_value,
                &result[2][i].trigger_value,
            ]
            .reconstruct();
            let b = [
                &result[0][i].active_bit,
                &result[1][i].active_bit,
                &result[2][i].active_bit,
            ]
            .reconstruct();

            assert_eq!(v.as_u128(), *value);
            assert_eq!(b.as_u128(), *active_bit);
        }
    }
}
