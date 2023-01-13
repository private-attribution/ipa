use super::{
    compute_b_bit, compute_stop_bit, if_else, CreditCappingInputRow, CreditCappingOutputRow,
    InteractionPatternStep,
};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::basics::SecureMul;
use crate::protocol::boolean::random_bits_generator::RandomBitsGenerator;
use crate::protocol::boolean::{local_secret_shared_bits, BitDecomposition, BitwiseLessThan};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::Replicated;
use futures::future::{try_join, try_join_all};
use std::iter::{repeat, zip};

///
/// # Errors
/// Propagates errors from multiplications
///
pub async fn credit_capping<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CreditCappingInputRow<F>],
    cap: u32,
) -> Result<Vec<CreditCappingOutputRow<F>>, Error> {
    //
    // Step 1. Initialize a local vector for the capping computation.
    //
    // * `original_credits` will have credit values of only source events
    //
    let original_credits = mask_source_credits(input, ctx.clone()).await?;

    //
    // Step 2. Compute user-level reversed prefix-sums
    //
    let prefix_summed_credits =
        credit_prefix_sum(ctx.clone(), input, original_credits.clone()).await?;

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
        ctx.clone(),
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
        .map(|(i, x)| CreditCappingOutputRow {
            breakdown_key: x.breakdown_key.clone(),
            credit: final_credits[i].clone(),
        })
        .collect::<Vec<_>>();

    Ok(output)
}

async fn mask_source_credits<F: Field>(
    input: &[CreditCappingInputRow<F>],
    ctx: SemiHonestContext<'_, F>,
) -> Result<Vec<Replicated<F>>, Error> {
    try_join_all(
        input
            .iter()
            .zip(zip(
                repeat(ctx.narrow(&Step::MaskSourceCredits)),
                repeat(ctx.share_of_one()),
            ))
            .enumerate()
            .map(|(i, (x, (ctx, one)))| async move {
                ctx.multiply(RecordId::from(i), &x.credit, &(one - &x.is_trigger_bit))
                    .await
            }),
    )
    .await
}

async fn credit_prefix_sum<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CreditCappingInputRow<F>],
    mut original_credits: Vec<Replicated<F>>,
) -> Result<Vec<Replicated<F>>, Error> {
    let one = ctx.share_of_one();
    let mut stop_bits = repeat(one.clone()).take(input.len()).collect::<Vec<_>>();

    let num_rows = input.len();

    for (depth, step_size) in std::iter::successors(Some(1_usize), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let c = ctx.narrow(&InteractionPatternStep::from(depth));
        let mut futures = Vec::with_capacity(end);

        // for each input row, create a future to execute secure multiplications
        for i in 0..end {
            let c = &c;
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_credit = &original_credits[i + step_size];
            let sibling_helper_bit = &input[i + step_size].helper_bit;
            futures.push(async move {
                // This block implements the below logic from MP-SPDZ code.
                //
                // b = stop_bit * successor.helper_bit
                // original_credit += b * successor.original_credit
                // stop_bit = b * successor.stop_bit

                let b = compute_b_bit(
                    c.narrow(&Step::BTimesStopBit),
                    record_id,
                    current_stop_bit,
                    sibling_helper_bit,
                    depth == 0,
                )
                .await?;

                try_join(
                    c.narrow(&Step::CurrentContributionBTimesSuccessorCredit)
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

        // accumulate the contribution from this iteration
        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                original_credits[i] += &credit;
                stop_bits[i] = stop_bit;
            });
    }

    Ok(original_credits.clone())
}

async fn is_credit_larger_than_cap<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    prefix_summed_credits: &[Replicated<F>],
    cap: u32,
) -> Result<Vec<Replicated<F>>, Error> {
    //TODO: `cap` is publicly known value for each query. We can avoid creating shares every time.
    let cap = local_secret_shared_bits(&ctx, cap.into());
    let random_bits_generator =
        RandomBitsGenerator::new(ctx.narrow(&Step::RandomBitsForBitDecomposition));
    let rbg = &random_bits_generator;

    try_join_all(
        prefix_summed_credits
            .iter()
            .zip(zip(repeat(ctx.clone()), repeat(cap)))
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
                    let compare_bit = BitwiseLessThan::execute(
                        ctx.narrow(&Step::IsCapLessThanCurrentContribution),
                        RecordId::from(i),
                        &cap,
                        &credit_bits,
                    )
                    .await?;
                    Ok::<_, Error>(compare_bit)
                }
            }),
    )
    .await
}

async fn compute_final_credits<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &[CreditCappingInputRow<F>],
    prefix_summed_credits: &[Replicated<F>],
    exceeds_cap_bits: &[Replicated<F>],
    original_credits: &[Replicated<F>],
    cap: u32,
) -> Result<Vec<Replicated<F>>, Error> {
    let num_rows = input.len();
    let cap = Replicated::from_scalar(ctx.role(), F::from(cap.into()));
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
                &Replicated::ZERO,
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
    BTimesStopBit,
    BTimesSuccessorStopBit,
    MaskSourceCredits,
    CurrentContributionBTimesSuccessorCredit,
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
            Self::BTimesStopBit => "b_times_stop_bit",
            Self::BTimesSuccessorStopBit => "b_times_successor_stop_bit",
            Self::MaskSourceCredits => "mask_source_credits",
            Self::CurrentContributionBTimesSuccessorCredit => {
                "current_contribution_b_times_successor_credit"
            }
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
    use crate::{
        ff::{Field, Fp32BitPrime},
        protocol::attribution::{
            credit_capping::credit_capping,
            tests::{generate_shared_input, BD, H, S, T},
        },
        test_fixture::{Reconstruct, TestWorld},
    };
    use futures_util::future::try_join3;
    use rand::rngs::mock::StepRng;

    #[tokio::test]
    pub async fn cap() {
        const CAP: u32 = 18;
        const TEST_CASE: &[[u128; 5]; 19] = &[
            // is_trigger, helper_bit, breakdown_key, credit, expected
            [S, H[0], BD[3], 0, 0],
            [S, H[0], BD[4], 0, 0],
            [S, H[1], BD[4], 19, 18],
            [T, H[1], BD[0], 19, 0],
            [T, H[1], BD[0], 9, 0],
            [T, H[1], BD[0], 7, 0],
            [T, H[1], BD[0], 6, 0],
            [T, H[1], BD[0], 1, 0],
            [S, H[0], BD[1], 0, 0],
            [T, H[0], BD[0], 10, 0],
            [S, H[0], BD[2], 15, 2],
            [T, H[1], BD[0], 15, 0],
            [T, H[1], BD[0], 12, 0],
            [S, H[1], BD[2], 0, 0],
            [S, H[1], BD[2], 10, 10],
            [T, H[1], BD[0], 10, 0],
            [T, H[1], BD[0], 4, 0],
            [S, H[1], BD[5], 6, 6],
            [T, H[1], BD[0], 6, 0],
        ];
        let expected = TEST_CASE.iter().map(|t| t[4]).collect::<Vec<_>>();

        //TODO: move to the new test framework
        let world = TestWorld::new().await;
        let context = world.contexts::<Fp32BitPrime>();
        let mut rng = StepRng::new(100, 1);

        let shares = generate_shared_input(TEST_CASE, &mut rng);

        let [c0, c1, c2] = context;
        let [s0, s1, s2] = shares;

        let h0_future = credit_capping(c0, &s0, CAP);
        let h1_future = credit_capping(c1, &s1, CAP);
        let h2_future = credit_capping(c2, &s2, CAP);

        let result = try_join3(h0_future, h1_future, h2_future).await.unwrap();

        assert_eq!(result.0.len(), TEST_CASE.len());
        assert_eq!(result.1.len(), TEST_CASE.len());
        assert_eq!(result.2.len(), TEST_CASE.len());
        assert_eq!(result.0.len(), expected.len());

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
}
