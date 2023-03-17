use super::{
    do_the_binary_tree_thing, if_else,
    input::{MCCreditCappingInputRow, MCCreditCappingOutputRow},
    prefix_or_binary_tree_style,
};
use crate::{
    error::Error,
    ff::{Field, PrimeField},
    protocol::{
        basics::SecureMul,
        boolean::{greater_than_constant, random_bits_generator::RandomBitsGenerator, RandomBits},
        context::Context,
        BasicProtocols, RecordId, Substep,
    },
    secret_sharing::Linear as LinearSecretSharing,
};
use futures::future::try_join_all;
use std::iter::{repeat, zip};

/// User-level credit capping protocol.
///
/// ## Errors
/// Fails if the multiplication protocol fails.
///
pub async fn credit_capping<F, C, T>(
    ctx: C,
    input: &[MCCreditCappingInputRow<F, T>],
    cap: u32,
) -> Result<Vec<MCCreditCappingOutputRow<F, T>>, Error>
where
    F: PrimeField,
    C: Context + RandomBits<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F>,
{
    if cap == 1 {
        return Ok(credit_capping_max_one(ctx, input)
            .await?
            .collect::<Vec<_>>());
    }
    let input_len = input.len();

    //
    // Step 1. Initialize a local vector for the capping computation.
    //
    // * `original_credits` will have credit values of only source events
    //
    let original_credits = mask_source_credits(input, ctx.set_total_records(input_len)).await?;

    //
    // Step 2. Compute user-level reversed prefix-sums
    //
    let prefix_summed_credits =
        credit_prefix_sum(ctx.clone(), input, original_credits.iter()).await?;

    //
    // 3. Compute `prefix_summed_credits` >? `cap`
    //
    // `exceeds_cap_bits` = 1 if `prefix_summed_credits` > `cap`
    //
    let exceeds_cap_bits =
        is_credit_larger_than_cap(ctx.clone(), &prefix_summed_credits, cap).await?;

    //
    // 4. Compute the `final_credit`
    //
    // We compute capped credits in the method, and writes to `original_credits`.
    //
    let final_credits = compute_final_credits(
        ctx.set_total_records(input_len),
        input,
        &prefix_summed_credits,
        &exceeds_cap_bits,
        &original_credits,
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
        prefix_or_binary_tree_style(ctx.clone(), &helper_bits[1..], &uncapped_credits[1..]).await?;

    let prefix_or_times_helper_bit_ctx = ctx
        .narrow(&Step::PrefixOrTimesHelperBit)
        .set_total_records(input.len() - 1);
    let ever_any_subsequent_credit =
        try_join_all(prefix_ors.iter().zip(helper_bits.iter()).enumerate().map(
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
    let capped_credits = try_join_all(
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
    try_join_all(
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
    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForComparison));
    let rbg = &random_bits_generator;

    try_join_all(
        prefix_summed_credits
            .iter()
            .zip(zip(
                repeat(ctx.set_total_records(prefix_summed_credits.len())),
                repeat(cap),
            ))
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
    let cap = T::share_known_value(&ctx, F::try_from(cap.into()).unwrap());
    let mut final_credits = original_credits.to_vec();

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

    for i in 0..(num_rows - 1) {
        let record_id = RecordId::from(i);

        let original_credit = &original_credits[i];
        let next_prefix_summed_credit = &prefix_summed_credits[i + 1];
        let current_prefix_summed_credit_exceeds_cap = &exceeds_cap_bits[i];
        let next_credit_exceeds_cap = &exceeds_cap_bits[i + 1];
        let next_event_has_same_match_key = &input[i + 1].helper_bit;

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
            &cap,
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

        final_credits[i] = capped_credit;
    }

    Ok(final_credits)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    MaskSourceCredits,
    RandomBitsForComparison,
    IsCapLessThanCurrentContribution,
    IfCurrentExceedsCapOrElse,
    IfNextExceedsCapOrElse,
    IfNextEventHasSameMatchKeyOrElse,
    PrefixOrTimesHelperBit,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MaskSourceCredits => "mask_source_credits",
            Self::RandomBitsForComparison => "random_bits_for_comparison",
            Self::IsCapLessThanCurrentContribution => "is_cap_less_than_current_contribution",
            Self::IfCurrentExceedsCapOrElse => "if_current_exceeds_cap_or_else",
            Self::IfNextExceedsCapOrElse => "if_next_exceeds_cap_or_else",
            Self::IfNextEventHasSameMatchKeyOrElse => "if_next_event_has_same_match_key_or_else",
            Self::PrefixOrTimesHelperBit => "prefix_or_times_helper_bit",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use crate::{
        accumulation_test_input,
        ff::{Field, Fp32BitPrime},
        protocol::{
            attribution::{
                credit_capping::credit_capping,
                input::{CreditCappingInputRow, MCCreditCappingInputRow},
            },
            context::Context,
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey,
        },
        secret_sharing::SharedValue,
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn cap() {
        const CAP: u32 = 18;
        const NUM_MULTI_BITS: u32 = 3;
        const EXPECTED: &[u128; 19] = &[0, 0, 18, 0, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 10, 0, 0, 6, 0];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = accumulation_test_input!(
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

        let world = TestWorld::default();
        let result = world
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

                    credit_capping(ctx, &modulus_converted_shares, CAP)
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
                &result[0][i].credit,
                &result[1][i].credit,
                &result[2][i].credit,
            ]
            .reconstruct();
            assert_eq!(v.as_u128(), *expected);
        }
    }
}
