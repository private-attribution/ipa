use super::{
    do_the_binary_tree_thing,
    input::{MCAccumulateCreditInputRow, MCAccumulateCreditOutputRow},
};
use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BasicProtocols, RecordId},
    secret_sharing::Linear as LinearSecretSharing,
};
use ipa_macros::step;
use std::num::NonZeroU32;
use strum::AsRefStr;

///
/// When `PER_USER_CAP` is set to one, this function is called
/// In this case, `trigger_value` is ignored entirely. Instead, each `trigger_report` counts as one.
/// So in the event that a `source report` is followed by multiple `trigger reports`, only one will count.
/// As such, this function can be simplified a great deal. All that matters is when a `source report` is
/// immediately followed by a `trigger report` from the same `match key`. As such, each row only needs to
/// be compared to the following row. This is done by multiplying the `is_trigger_report` by the `helper_bit`,
/// which is what `stop_bits` is.
/// If there are multiple attributed conversions from the same `match key` they will be removed in the
/// next stage; `user capping`.
///
/// This method implements "last touch" attribution, so only the last `source report` before a `trigger report`
/// will receive any credit.
async fn accumulate_credit_cap_one<'a, F, C, T>(
    ctx: C,
    input: &'a [MCAccumulateCreditInputRow<F, T>],
    stop_bits: &'a [T],
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<impl Iterator<Item = MCAccumulateCreditOutputRow<F, T>> + 'a, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    // if `attribution_window_seconds` is not set, we use `stop_bits` directly. Otherwise, we need to invalidate
    // reports that are outside the attribution window by multiplying them by `active_bit`. active_bit is
    // 0 if the trigger report's time-delta to the nearest source report is greater than the attribution window.
    let attributed_trigger_reports_in_window = if attribution_window_seconds.is_none() {
        stop_bits.to_vec()
    } else {
        let memoize_context = ctx
            .narrow(&Step::ActiveBitTimesStopBit)
            .set_total_records(input.len() - 1);
        ctx.try_join(
            input
                .iter()
                .skip(1)
                .zip(stop_bits)
                .enumerate()
                .map(|(i, (x, sb))| {
                    let c = memoize_context.clone();
                    let record_id = RecordId::from(i);
                    async move { x.active_bit.multiply(sb, c, record_id).await }
                }),
        )
        .await?
    };

    let output = input
        .iter()
        .zip(attributed_trigger_reports_in_window)
        .map(|(x, bit)| {
            MCAccumulateCreditOutputRow::new(
                x.is_trigger_report.clone(),
                x.helper_bit.clone(),
                x.breakdown_key.clone(),
                bit,
            )
        });

    Ok(output)
}

/// The accumulation step operates on a sorted list with O(log N) iterations, where N is the input length.
/// It is the first step of the Oblivious Attribution protocol, and subsequent steps of all attribution models
/// (i.e., last touch, equal credit) use an output produced by this step. During each iteration, it accesses each
/// list element once, establishing a tree-like structure in which, starting from the leaf nodes, each node
/// accesses and accumulates data of its children. By increasing the distance between the interacting nodes during
/// each iteration by a factor of two, we ensure that each node only accumulates the value of each successor only once.
/// <https://github.com/patcg-individual-drafts/ipa/blob/main/IPA-End-to-End.md#oblivious-last-touch-attribution>
///
/// # Errors
///
/// Fails if the multiplication fails.
#[tracing::instrument(name = "accumulate_credit", skip_all)]
pub async fn accumulate_credit<F, C, T>(
    ctx: C,
    input: &[MCAccumulateCreditInputRow<F, T>],
    stop_bits: &[T],
    per_user_credit_cap: u32,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<MCAccumulateCreditOutputRow<F, T>>, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    if per_user_credit_cap == 1 {
        return Ok(
            accumulate_credit_cap_one(ctx, input, stop_bits, attribution_window_seconds)
                .await?
                .collect::<Vec<_>>(),
        );
    }

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
    do_the_binary_tree_thing(ctx, stop_bits.to_vec(), &mut credits).await?;

    let output = input
        .iter()
        .enumerate()
        .map(|(i, x)| {
            MCAccumulateCreditOutputRow::new(
                x.is_trigger_report.clone(),
                x.helper_bit.clone(),
                x.breakdown_key.clone(),
                credits[i].clone(),
            )
        })
        .collect::<Vec<_>>();

    Ok(output)
}

#[step]
pub(crate) enum Step {
    ActiveBitTimesStopBit,
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{iter, num::NonZeroU32};

    use crate::{
        accumulation_test_input,
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::Role,
        protocol::{
            attribution::{
                accumulate_credit::accumulate_credit,
                compute_stop_bits,
                input::{
                    AccumulateCreditInputRow, MCAccumulateCreditInputRow,
                    MCAccumulateCreditOutputRow,
                },
            },
            basics::Reshare,
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey, RecordId,
        },
        rand::thread_rng,
        secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, SharedValue},
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };
    use rand::Rng;

    async fn accumulate_credit_test(
        input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>>,
        cap: u32,
        attribution_window_seconds: Option<NonZeroU32>,
    ) -> [Vec<MCAccumulateCreditOutputRow<Fp32BitPrime, Replicated<Fp32BitPrime>>>; 3] {
        let world = TestWorld::default();

        world
            .semi_honest(
                input.into_iter(),
                |ctx, input: Vec<AccumulateCreditInputRow<Fp32BitPrime, BreakdownKey>>| async move {
                    let bk_shares = input.iter().map(|x| x.breakdown_key.clone());

                    let mut converted_bk_shares = convert_all_bits(
                        &ctx,
                        &convert_all_bits_local(ctx.role(), bk_shares),
                        BreakdownKey::BITS,
                        BreakdownKey::BITS,
                    )
                    .await
                    .unwrap();
                    let converted_bk_shares = converted_bk_shares.pop().unwrap();
                    let modulus_converted_shares = input
                        .iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| {
                            MCAccumulateCreditInputRow::new(
                                row.is_trigger_report.clone(),
                                row.helper_bit.clone(),
                                row.active_bit.clone(),
                                bk,
                                row.trigger_value.clone(),
                            )
                        })
                        .collect::<Vec<_>>();

                    let (itb, hb): (Vec<_>, Vec<_>) = input
                        .iter()
                        .map(|x| (x.is_trigger_report.clone(), x.helper_bit.clone()))
                        .unzip();
                    let stop_bits = compute_stop_bits(ctx.clone(), &itb, &hb)
                        .await
                        .unwrap()
                        .collect::<Vec<_>>();

                    accumulate_credit(
                        ctx,
                        &modulus_converted_shares,
                        &stop_bits,
                        cap,
                        attribution_window_seconds,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
    }

    // If the cap > 1, the protocol proceeds with the normal binary-tree prefix-sum thing.
    #[tokio::test]
    pub async fn accumulate_basic() {
        const EXPECTED: &[u128; 21] = &[
            0, 0, 19, 19, 9, 7, 6, 1, 0, 0, 0, 10, 15, 15, 12, 0, 10, 10, 4, 6, 6,
        ];
        const PER_USER_CAP: u32 = 3; // can be anything but 1
        const ATTRIBUTION_WINDOW_SECONDS: Option<NonZeroU32> = None; // no attribution window = all reports are valid

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 3, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW_SECONDS).await;

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

    /// If the cap = 1 and attribution_window_seconds = 0, then the expected result is the same as
    /// `is_trigger_report` * `helper_bit` (= `stop_bit`). In other words, it counts all matching
    /// trigger reports.
    #[tokio::test]
    pub async fn accumulate_cap_of_one_without_attribution_window() {
        const EXPECTED: &[u128; 20] = &[0, 0, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1];
        const PER_USER_CAP: u32 = 1;
        const ATTRIBUTION_WINDOW_SECONDS: Option<NonZeroU32> = None;

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 3, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW_SECONDS).await;

        assert_eq!(result[0].len(), input_len - 1);
        assert_eq!(result[1].len(), input_len - 1);
        assert_eq!(result[2].len(), input_len - 1);
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

    /// If the cap = 1 and attribution_window_seconds > 0, then the expected result is the same as
    /// `is_trigger_report` * `helper_bit` * `active_bit`. In other words, it counts all matching
    /// trigger reports that are within the given attribution window.
    #[tokio::test]
    pub async fn accumulate_cap_of_one_with_attribution_window() {
        const EXPECTED: &[u128; 20] = &[0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1];
        const PER_USER_CAP: u32 = 1;
        const ATTRIBUTION_WINDOW_SECONDS: Option<NonZeroU32> = NonZeroU32::new(1);

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 3, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, breakdown_key: 0, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 0, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, breakdown_key: 5, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW_SECONDS).await;

        assert_eq!(result[0].len(), input_len - 1);
        assert_eq!(result[1].len(), input_len - 1);
        assert_eq!(result[2].len(), input_len - 1);
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
                active_bit: rng.gen::<u8>(),
                breakdown_key: rng.gen::<u8>(),
                credit: rng.gen::<u8>(),
            };
            (Fp31, MathKey, BreakdownKey)
        );

        let world = TestWorld::default();
        for &role in Role::all() {
            let new_shares = world
                .semi_honest(
                    secret,
                    |ctx, share: AccumulateCreditInputRow<Fp31, BreakdownKey>| async move {
                        let bk_shares = iter::once(share.breakdown_key);
                        let mut converted_bk_shares = convert_all_bits(
                            &ctx,
                            &convert_all_bits_local(ctx.role(), bk_shares),
                            BreakdownKey::BITS,
                            BreakdownKey::BITS,
                        )
                        .await
                        .unwrap();
                        let converted_bk_shares = converted_bk_shares.pop().unwrap();

                        let modulus_converted_share = MCAccumulateCreditInputRow::new(
                            share.is_trigger_report,
                            share.helper_bit,
                            share.active_bit,
                            converted_bk_shares.into_iter().next().unwrap(),
                            share.trigger_value,
                        );

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
