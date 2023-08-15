use std::num::NonZeroU32;

use ipa_macros::step;
use strum::AsRefStr;

use super::{
    do_the_binary_tree_thing,
    input::{AccumulateCreditInputRow, AccumulateCreditOutputRow},
};
use crate::{
    error::Error,
    ff::Field,
    protocol::{context::Context, BasicProtocols, RecordId},
    secret_sharing::Linear as LinearSecretSharing,
};

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
    input: &'a [AccumulateCreditInputRow<F, T>],
    stop_bits: &'a [T],
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<impl Iterator<Item = AccumulateCreditOutputRow<F, T>> + 'a, Error>
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
            AccumulateCreditOutputRow::new(x.is_trigger_report.clone(), x.helper_bit.clone(), bit)
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
    input: &[AccumulateCreditInputRow<F, T>],
    stop_bits: &[T],
    per_user_credit_cap: u32,
    attribution_window_seconds: Option<NonZeroU32>,
) -> Result<Vec<AccumulateCreditOutputRow<F, T>>, Error>
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
            AccumulateCreditOutputRow::new(
                x.is_trigger_report.clone(),
                x.helper_bit.clone(),
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
    use std::num::NonZeroU32;

    use crate::{
        accumulation_test_input,
        ff::Fp32BitPrime,
        protocol::{
            attribution::{
                accumulate_credit::accumulate_credit, compute_stop_bits,
                input::AccumulateCreditInputRow,
            },
            context::{UpgradableContext, Validator},
            BreakdownKey, MatchKey,
        },
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    async fn accumulate_credit_test(
        input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>>,
        cap: u32,
        attribution_window_seconds: Option<NonZeroU32>,
    ) -> Vec<Fp32BitPrime> {
        type InputType = Vec<AccumulateCreditInputRow<Fp32BitPrime, Replicated<Fp32BitPrime>>>;
        TestWorld::default()
            .semi_honest(input.into_iter(), |ctx, input: InputType| async move {
                let validator = &ctx.validator::<Fp32BitPrime>();
                let ctx = validator.context(); // Ignore the validator for this test.

                let (itb, hb): (Vec<_>, Vec<_>) = input
                    .iter()
                    .map(|x| (x.is_trigger_report.clone(), x.helper_bit.clone()))
                    .unzip();
                // Note that computing stop bits requires that the first helper bit be skipped.
                let stop_bits = compute_stop_bits(ctx.clone(), &itb, &hb[1..])
                    .await
                    .unwrap()
                    .collect::<Vec<_>>();

                accumulate_credit(ctx, &input, &stop_bits, cap, attribution_window_seconds)
                    .await
                    .unwrap()
            })
            .await
            // We only need the trigger values.
            .map(|share| {
                share
                    .into_iter()
                    .map(|r| r.trigger_value)
                    .collect::<Vec<_>>()
            })
            .reconstruct()
    }

    // If the cap > 1, the protocol proceeds with the normal binary-tree prefix-sum thing.
    #[tokio::test]
    pub async fn accumulate_basic() {
        const EXPECTED: &[u128; 21] = &[
            0, 0, 19, 19, 9, 7, 6, 1, 0, 0, 0, 10, 15, 15, 12, 0, 10, 10, 4, 6, 6,
        ];
        const PER_USER_CAP: u32 = 3; // can be anything but 1
        const ATTRIBUTION_WINDOW: Option<NonZeroU32> = None; // no attribution window = all reports are valid

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 }, // 0
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 }, // 0
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 }, // 19
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 10 }, // 19
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 2 }, // 9
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 }, // 7
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 5 }, // 6
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 }, // 1
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 }, // 0
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 }, // 0
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 }, // 0
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, credit: 10 }, // 10
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 }, // 0 (!) or 15?
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 3 }, // 15
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 12 }, // 12
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 }, // 0
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 }, // 10
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 }, // 10
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 4 }, // 4
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 }, // 6
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 }, // 6
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW).await;
        assert_eq!(result, EXPECTED);
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
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW_SECONDS).await;
        assert_eq!(result, EXPECTED);
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
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 5 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 1 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 0, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, active_bit: 1, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 3 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, active_bit: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 1, active_bit: 1, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let result = accumulate_credit_test(input, PER_USER_CAP, ATTRIBUTION_WINDOW_SECONDS).await;
        assert_eq!(result, EXPECTED);
    }
}
