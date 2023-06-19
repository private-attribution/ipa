use super::{
    do_the_binary_tree_thing,
    input::{MCCreditCappingInputRow, MCCreditCappingOutputRow},
    prefix_or_binary_tree_style,
};
use crate::{
    error::Error,
    ff::{Field, PrimeField},
    protocol::{
        basics::{if_else, SecureMul},
        boolean::{greater_than_constant, random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
    seq_join::seq_join,
};
use futures::{
    stream::{iter, once},
    StreamExt, TryStreamExt,
};
use std::iter::{repeat, zip};

/// User-level credit capping protocol.
///
/// ## Errors
/// Fails if the multiplication protocol fails, or if the `cap` is larger than
/// 1/2 of the prime number.
#[tracing::instrument(name = "user_capping", skip_all)]
pub async fn credit_capping<F, C, S>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, S>],
    cap: u32,
) -> Result<Vec<MCCreditCappingOutputRow<F, S>>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    if cap == 1 {
        return Ok(credit_capping_max_one(ctx, input)
            .await?
            .collect::<Vec<_>>());
    }
    let input_len = input.len();

    if (u128::from(cap) * 2) >= F::PRIME.into() {
        return Err(crate::error::Error::InvalidQueryParameter(format!(
            "The cap {cap} must be less than 1/2 of the prime modulus to make overflow detectable, and propagable."
        )));
    }

    //
    // Step 1. Initialize a local vector for the capping computation.
    //
    // * `original_credits` will have credit values of only source events
    //
    let original_credits = mask_source_credits(input, ctx.set_total_records(input_len)).await?;

    //
    // Step 2. Cap each report's value to `cap`
    //
    // Returns a vector of report values that are capped at `cap`. The cap is known to be
    // less than 1/2 of the prime number used for the field.
    //
    // This initial capping step is applied to each report value individually, rather than
    // to the prefixed sum of matching report values in the later steps. This is required to
    // detect a possible overflow in the `credit_prefix_sum` step, which leads to an individual's
    // contribution to exceed the cap. (issue #520)
    //
    // This step ensures that the prefixed summed report values computed in `credit_prefix_sum`
    // step will have at least one row with a value that is larger than the cap and less than
    // the prime number, if overflows were to happen.
    //
    // For example, if the prime number is 31 and the cap is 15, then the reversed prefixed sum
    // of [].., 15, 15, 15] will be [..., 15, 30, 15]. Then `is_credit_larger_than_cap` step will
    // catch that the second to last row is larger than the cap.
    //
    // This step alone does not prevent the overflow from happening, but if we compute the
    // reversed prefix-OR of the `is_credit_larger_than_cap` step, then we can apply the cap to
    // all rows that precede the most recent row with a value larger than the cap.
    //
    let capped_credits = report_level_capping(ctx.clone(), &original_credits, cap).await?;

    //
    // Step 3. Compute user-level reversed prefix-sums
    //
    let prefix_summed_credits =
        credit_prefix_sum(ctx.clone(), input, capped_credits.iter()).await?;

    //
    // Step 4. Compute `prefix_summed_credits` >? `cap`
    //
    // `exceeds_cap_bits` = 1 if `prefix_summed_credits` > `cap`
    //
    let exceeds_cap_bits =
        is_credit_larger_than_cap(ctx.clone(), &prefix_summed_credits, cap).await?;

    //
    // Step 5. Compute the reversed prefix-OR of `exceeds_cap_bits`
    //
    //
    // This step ensures that once the comparison "credit > cap" is true, then the true value
    // will be propagated to all the rows that precede the row with the true value. The next
    // step `compute_final_credits` will then check these bits and set the credit to zero.
    //
    let prefix_or_exceeds_cap_bits =
        propagate_overflow_detection(ctx.clone(), input, exceeds_cap_bits).await?;

    //
    // Step 6. Compute user-level capped credits.
    //
    // This protocol caps the user-level credits from the oldest report to the newest report,
    // meaning that older reports will be capped if the user's contribution has already exceeded
    // the cap. We can change the logic to do the opposite, i.e. cap the newest reports first, by
    // reversing the order of the input.
    //
    let final_credits = compute_final_credits(
        ctx,
        input,
        &prefix_summed_credits,
        &prefix_or_exceeds_cap_bits,
        &capped_credits,
        cap,
    )
    .await?;

    let output = input
        .iter()
        .enumerate()
        .map(|(i, x)| {
            MCCreditCappingOutputRow::new(x.breakdown_key.clone(), final_credits[i].clone())
        })
        .collect::<Vec<_>>();

    Ok(output)
}

///
/// User-level credit capping protocol that is run when `PER_USER_CAP == 1`
///
/// In this mode, `trigger_value` is completely ignored. Each trigger event counts as just one.
///
/// Since each user can *at most* contribute just one, if there are multiple attributed conversions
/// from the same `match key`, we need some way of deciding which one to keep. This current implementation
/// only keeps the *last attributed conversion*.
/// This is implemented by virtue of computing a prefix-OR of all of the attributed conversions from
/// a given `match-key`, starting at each row.
/// In the final step, each row is compared with the prefix-OR of the following row. If the following row
/// is from the same `match-key`, and the prefix-OR indicates that there is *at least one* attributed conversion
/// in the following rows, then the contribution is "capped", which in this context means set to zero.
/// In this way, only the final attributed conversion will not be "capped".
async fn credit_capping_max_one<F, C, T>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, T>],
) -> Result<impl Iterator<Item = MCCreditCappingOutputRow<F, T>> + '_, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let input_len = input.len();

    let uncapped_credits = mask_source_credits(input, ctx.set_total_records(input_len)).await?;

    let helper_bits = input
        .iter()
        .skip(1)
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    let prefix_ors =
        prefix_or_binary_tree_style(ctx.clone(), &helper_bits[1..], &uncapped_credits[1..], true)
            .await?;

    let prefix_or_times_helper_bit_ctx = ctx
        .narrow(&Step::PrefixOrTimesHelperBit)
        .set_total_records(input.len() - 1);
    let ever_any_subsequent_credit = ctx
        .try_join(prefix_ors.iter().zip(helper_bits.iter()).enumerate().map(
            |(i, (prefix_or, helper_bit))| {
                let record_id = RecordId::from(i);
                let c = prefix_or_times_helper_bit_ctx.clone();
                async move { prefix_or.multiply(helper_bit, c, record_id).await }
            },
        ))
        .await?;

    let potentially_cap_ctx = ctx
        .narrow(&Step::IfCurrentExceedsCapOrElse)
        .set_total_records(input.len() - 1);
    let capped_credits = ctx
        .try_join(
            uncapped_credits
                .iter()
                .zip(ever_any_subsequent_credit.iter())
                .enumerate()
                .map(|(i, (uncapped_credit, any_subsequent_credit))| {
                    let record_id = RecordId::from(i);
                    let c = potentially_cap_ctx.clone();
                    let one = T::share_known_value(&c, F::ONE);
                    async move {
                        uncapped_credit
                            .multiply(&(one - any_subsequent_credit), c, record_id)
                            .await
                    }
                }),
        )
        .await?;

    let output = input.iter().enumerate().map(move |(i, x)| {
        let credit = if i < capped_credits.len() {
            &capped_credits[i]
        } else {
            &uncapped_credits[i]
        };
        MCCreditCappingOutputRow::new(x.breakdown_key.clone(), credit.clone())
    });

    Ok(output)
}

async fn mask_source_credits<F, C, T>(
    input: &[MCCreditCappingInputRow<F, T>],
    ctx: C,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    ctx.try_join(
        input
            .iter()
            .zip(zip(
                repeat(ctx.narrow(&Step::MaskSourceCredits)),
                repeat(T::share_known_value(&ctx, F::ONE)),
            ))
            .enumerate()
            .map(|(i, (x, (ctx, one)))| async move {
                x.trigger_value
                    .multiply(&(one - &x.is_trigger_report), ctx, RecordId::from(i))
                    .await
            }),
    )
    .await
}

async fn report_level_capping<F, C, T>(
    ctx: C,
    original_credits: &[T],
    cap: u32,
) -> Result<Vec<T>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let share_of_cap = T::share_known_value(&ctx, F::truncate_from(cap));
    let cap_ref = &share_of_cap;
    let exceeds_cap_bits =
        is_credit_larger_than_cap(ctx.narrow(&Step::ReportLevelCapping), original_credits, cap)
            .await?;

    let if_else_ctx = ctx
        .narrow(&Step::IfReportCreditExceedsCapOrElse)
        .set_total_records(original_credits.len());

    ctx.try_join(zip(original_credits, exceeds_cap_bits.iter()).enumerate().map(
        |(i, (original_credit, exceeds_cap_bit))| {
            let record_id = RecordId::from(i);
            let c = if_else_ctx.clone();
            async move { if_else(c, record_id, exceeds_cap_bit, cap_ref, original_credit).await }
        },
    ))
    .await
}

async fn credit_prefix_sum<'a, F, C, T, I>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, T>],
    original_credits: I,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + SecureMul<C> + 'a,
    I: Iterator<Item = &'a T>,
{
    let helper_bits = input
        .iter()
        .skip(1)
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    let mut credits = original_credits.cloned().collect::<Vec<_>>();

    do_the_binary_tree_thing(ctx, helper_bits, &mut credits).await?;

    Ok(credits)
}

async fn is_credit_larger_than_cap<F, C, T>(
    ctx: C,
    prefix_summed_credits: &[T],
    cap: u32,
) -> Result<Vec<T>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let ctx_ref = &ctx;
    let ctx = ctx.set_total_records(prefix_summed_credits.len());
    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForComparison));
    let rbg = &random_bits_generator;

    ctx_ref
        .try_join(
            prefix_summed_credits
                .iter()
                .zip(zip(repeat(ctx), repeat(cap)))
                .enumerate()
                .map(|(i, (credit, (ctx, cap)))| {
                    greater_than_constant(
                        ctx.narrow(&Step::IsCapLessThanCurrentContribution),
                        RecordId::from(i),
                        rbg,
                        credit,
                        cap.into(),
                    )
                }),
        )
        .await
}

async fn propagate_overflow_detection<F, C, T>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, T>],
    exceeds_cap_bits: Vec<T>,
) -> Result<Vec<T>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let helper_bits = input
        .iter()
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    prefix_or_binary_tree_style(
        ctx.narrow(&Step::PrefixOrCompareBits),
        &helper_bits[1..],
        &exceeds_cap_bits,
        false,
    )
    .await
}

async fn compute_final_credits<F, C, T>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, T>],
    prefix_summed_credits: &[T],
    exceeds_cap_bits: &[T],
    original_credits: &[T],
    cap: u32,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    let num_rows = input.len();
    let cap_share = T::share_known_value(&ctx, F::try_from(cap.into()).unwrap());
    let cap = &cap_share;

    // This method implements the logic below:
    //
    //   if current_credit_exceeds_cap {
    //     if next_event_has_same_match_key {
    //       if next_credit_exceeds_cap {
    //         0
    //       } else {
    //         cap - next_prefix_summed_credit
    //       }
    //     } else {
    //       cap
    //     }
    //   } else {
    //     current_credit
    //   }

    let capped = zip(
        repeat(ctx.set_total_records(num_rows - 1)).enumerate(),
        zip(
            zip(
                // Take the original credit at the current line
                // and the prefix-summed credit at the next line.
                zip(original_credits, &prefix_summed_credits[1..]),
                // Then the exceeds cap bits on both lines.
                exceeds_cap_bits.windows(2),
            ),
            // Get the helper bit from the next line.
            input[1..].iter().map(|i| &i.helper_bit),
        ),
    )
    .map(
        |(
            (i, ctx),
            (
                ((original_credit, next_prefix_summed_credit), exceeds_cap),
                next_event_has_same_match_key,
            ),
        )| async move {
            let record_id = RecordId::from(i);
            let current_prefix_summed_credit_exceeds_cap = &exceeds_cap[0];
            let next_credit_exceeds_cap = &exceeds_cap[1];

            let remaining_budget = if_else(
                ctx.narrow(&Step::IfNextEventHasSameMatchKeyOrElse),
                record_id,
                next_event_has_same_match_key,
                &if_else(
                    ctx.narrow(&Step::IfNextExceedsCapOrElse),
                    record_id,
                    next_credit_exceeds_cap,
                    &T::ZERO,
                    &(cap.clone() - next_prefix_summed_credit),
                )
                .await?,
                cap,
            )
            .await?;

            let capped_credit = if_else(
                ctx.narrow(&Step::IfCurrentExceedsCapOrElse),
                record_id,
                current_prefix_summed_credit_exceeds_cap,
                &remaining_budget,
                original_credit,
            )
            .await?;

            Ok::<_, Error>(capped_credit)
        },
    );

    let last = original_credits.last().ok_or(Error::Internal).cloned();

    seq_join(ctx.active_work(), iter(capped))
        .chain(once(async { last }))
        .try_collect()
        .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    MaskSourceCredits,
    ReportLevelCapping,
    IfReportCreditExceedsCapOrElse,
    RandomBitsForComparison,
    IsCapLessThanCurrentContribution,
    IfCurrentExceedsCapOrElse,
    IfNextExceedsCapOrElse,
    IfNextEventHasSameMatchKeyOrElse,
    PrefixOrTimesHelperBit,
    PrefixOrCompareBits,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MaskSourceCredits => "mask_source_credits",
            Self::ReportLevelCapping => "report_level_capping",
            Self::IfReportCreditExceedsCapOrElse => "if_report_credit_exceeds_cap_or_else",
            Self::RandomBitsForComparison => "random_bits_for_comparison",
            Self::IsCapLessThanCurrentContribution => "is_cap_less_than_current_contribution",
            Self::IfCurrentExceedsCapOrElse => "if_current_exceeds_cap_or_else",
            Self::IfNextExceedsCapOrElse => "if_next_exceeds_cap_or_else",
            Self::IfNextEventHasSameMatchKeyOrElse => "if_next_event_has_same_match_key_or_else",
            Self::PrefixOrTimesHelperBit => "prefix_or_times_helper_bit",
            Self::PrefixOrCompareBits => "prefix_or_compare_bits",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{
        credit_capping_test_input,
        ff::{Field, Fp32BitPrime, PrimeField},
        protocol::{
            attribution::{
                credit_capping::credit_capping,
                input::{CreditCappingInputRow, MCCreditCappingInputRow, MCCreditCappingOutputRow},
            },
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey,
        },
        secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    async fn run_credit_capping_test(
        input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>>,
        cap: u32,
    ) -> [Vec<MCCreditCappingOutputRow<Fp32BitPrime, AdditiveShare<Fp32BitPrime>>>; 3] {
        let world = TestWorld::default();
        world
            .semi_honest(
                input,
                |ctx, input: Vec<CreditCappingInputRow<Fp32BitPrime, BreakdownKey>>| async move {
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
                            MCCreditCappingInputRow::new(
                                row.is_trigger_report.clone(),
                                row.helper_bit.clone(),
                                bk,
                                row.trigger_value.clone(),
                            )
                        })
                        .collect::<Vec<_>>();

                    credit_capping(ctx, &modulus_converted_shares, cap)
                        .await
                        .unwrap()
                },
            )
            .await
    }

    #[tokio::test]
    pub async fn basic() {
        const CAP: u32 = 18;
        const EXPECTED: &[u128; 19] = &[0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 6, 0];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = credit_capping_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 3, credit: 0 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 4, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 4, credit: 19 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 19 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 9 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 7 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 1 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 0 },
                { is_trigger_report: 1, helper_bit: 0, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 2, credit: 15 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 15 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 12 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 0 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 2, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 10 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 4 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 5, credit: 6 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 6 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = run_credit_capping_test(input, CAP).await;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);
        assert_eq!(result[0].len(), EXPECTED.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = [
                &result[0][i].credit,
                &result[1][i].credit,
                &result[2][i].credit,
            ]
            .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }

    #[tokio::test]
    #[should_panic]
    pub async fn invalid_cap_value() {
        // Input doesn't matter here, since the test should panic before the computation starts.
        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = credit_capping_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 2 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );

        // This should panic because the cap value is greater than the (prime / 2).
        run_credit_capping_test(input, (Fp32BitPrime::PRIME / 2) + 1).await;
    }

    // This test case is to test where `exceeds_cap_bit` yields alternating {0, 1} bits.
    // See #520 for more details.
    #[tokio::test]
    pub async fn wrapping_add_attack_case_1() {
        const MINUS_TWO: u32 = Fp32BitPrime::PRIME - 2;
        const CAP: u32 = 2;
        const EXPECTED: &[u128; 8] = &[0, 0, 0, 0, 0, 0, 2, 0];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = credit_capping_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: MINUS_TWO },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: MINUS_TWO },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: MINUS_TWO },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: MINUS_TWO },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = run_credit_capping_test(input, CAP).await;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);
        assert_eq!(result[0].len(), EXPECTED.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = [
                &result[0][i].credit,
                &result[1][i].credit,
                &result[2][i].credit,
            ]
            .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }

    // This test case is to test where `exceeds_cap_bit` yields all 0's.
    // See #520 for more details.
    #[tokio::test]
    pub async fn wrapping_add_attack_case_2() {
        const MINUS_TWO: u32 = Fp32BitPrime::PRIME - 2;
        const CAP: u32 = 2;
        const EXPECTED: &[u128; 8] = &[0, 0, 0, 0, 0, 0, 2, 0];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = credit_capping_test_input!(
            [
                { is_trigger_report: 0, helper_bit: 0, breakdown_key: 1, credit: MINUS_TWO },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: MINUS_TWO },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: MINUS_TWO },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: MINUS_TWO },
                { is_trigger_report: 0, helper_bit: 1, breakdown_key: 1, credit: 2 },
                { is_trigger_report: 1, helper_bit: 1, breakdown_key: 0, credit: 2 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );
        let input_len = input.len();

        let result = run_credit_capping_test(input, CAP).await;

        assert_eq!(result[0].len(), input_len);
        assert_eq!(result[1].len(), input_len);
        assert_eq!(result[2].len(), input_len);
        assert_eq!(result[0].len(), EXPECTED.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = [
                &result[0][i].credit,
                &result[1][i].credit,
                &result[2][i].credit,
            ]
            .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }
}
