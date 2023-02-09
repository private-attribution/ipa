use super::{
    do_the_binary_tree_thing, if_else,
    input::{MCCreditCappingInputRow, MCCreditCappingOutputRow},
};
use crate::ff::Field;
use crate::protocol::boolean::random_bits_generator::RandomBitsGenerator;
use crate::protocol::boolean::{bitwise_greater_than_constant, BitDecomposition};
use crate::protocol::context::Context;
use crate::protocol::{RecordId, Substep};
use crate::{error::Error, secret_sharing::Arithmetic};
use futures::future::try_join_all;
use std::{
    iter::{repeat, zip},
    marker::PhantomData,
};

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
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
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
        .map(|(i, x)| MCCreditCappingOutputRow {
            breakdown_key: x.breakdown_key.clone(),
            credit: final_credits[i].clone(),
            _marker: PhantomData::default(),
        })
        .collect::<Vec<_>>();

    Ok(output)
}

async fn mask_source_credits<F, C, T>(
    input: &[MCCreditCappingInputRow<F, T>],
    ctx: C,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    try_join_all(
        input
            .iter()
            .zip(zip(
                repeat(ctx.narrow(&Step::MaskSourceCredits)),
                repeat(ctx.share_known_value(F::ONE)),
            ))
            .enumerate()
            .map(|(i, (x, (ctx, one)))| async move {
                ctx.multiply(
                    RecordId::from(i),
                    &x.trigger_value,
                    &(one - &x.is_trigger_report),
                )
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
    C: Context<F, Share = T>,
    T: Arithmetic<F> + 'a,
    I: Iterator<Item = &'a T>,
{
    let helper_bits = input
        .iter()
        .skip(1)
        .map(|x| x.helper_bit.clone())
        .collect::<Vec<_>>();

    do_the_binary_tree_thing(ctx, &helper_bits, original_credits).await
}

async fn is_credit_larger_than_cap<F, C, T>(
    ctx: C,
    prefix_summed_credits: &[T],
    cap: u32,
) -> Result<Vec<T>, Error>
where
    F: Field,
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    //TODO: `cap` is publicly known value for each query. We can avoid creating shares every time.
    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForBitDecomposition));
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
                // The buffer inside the generator is `Arc`, so these clones
                // just increment the reference.
                async move {
                    let credit_bits = BitDecomposition::execute(
                        ctx.narrow(&Step::BitDecomposeCurrentContribution),
                        RecordId::from(i),
                        rbg,
                        credit,
                    )
                    .await?;

                    // compare_bit = current_contribution > cap
                    let compare_bit = bitwise_greater_than_constant(
                        ctx.narrow(&Step::IsCapLessThanCurrentContribution),
                        RecordId::from(i),
                        &credit_bits,
                        cap.into(),
                    )
                    .await?;
                    Ok::<_, Error>(compare_bit)
                }
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
    C: Context<F, Share = T>,
    T: Arithmetic<F>,
{
    let num_rows = input.len();
    let cap = ctx.share_known_value(F::from(cap.into()));
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
    BitDecomposeCurrentContribution,
    RandomBitsForBitDecomposition,
    IsCapLessThanCurrentContribution,
    IfCurrentExceedsCapOrElse,
    IfNextExceedsCapOrElse,
    IfNextEventHasSameMatchKeyOrElse,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::MaskSourceCredits => "mask_source_credits",
            Self::BitDecomposeCurrentContribution => "bit_decompose_current_contribution",
            Self::RandomBitsForBitDecomposition => "random_bits_for_bit_decomposition",
            Self::IsCapLessThanCurrentContribution => "is_cap_less_than_current_contribution",
            Self::IfCurrentExceedsCapOrElse => "if_current_exceeds_cap_or_else",
            Self::IfNextExceedsCapOrElse => "if_next_exceeds_cap_or_else",
            Self::IfNextEventHasSameMatchKeyOrElse => "if_next_event_has_same_match_key_or_else",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::marker::PhantomData;

    use crate::{
        accumulation_test_input,
        ff::{Field, Fp32BitPrime},
        protocol::attribution::{
            credit_capping::credit_capping,
            input::{CreditCappingInputRow, MCCreditCappingInputRow},
        },
        protocol::modulus_conversion::{combine_slices, convert_all_bits, convert_all_bits_local},
        protocol::{
            context::Context,
            {BreakdownKey, MatchKey},
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

        let world = TestWorld::new().await;
        let result = world
            .semi_honest(
                input,
                |ctx, input: Vec<CreditCappingInputRow<Fp32BitPrime, BreakdownKey>>| async move {
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
                        combine_slices(converted_bk_shares.iter(), input_len, BreakdownKey::BITS);
                    let modulus_converted_shares = input
                        .iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCCreditCappingInputRow {
                            is_trigger_report: row.is_trigger_report.clone(),
                            breakdown_key: bk,
                            trigger_value: row.trigger_value.clone(),
                            helper_bit: row.helper_bit.clone(),
                            _marker: PhantomData::default(),
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
