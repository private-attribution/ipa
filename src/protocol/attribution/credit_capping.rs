use super::{CreditCappingInputRow, CreditCappingOutputRow, InteractionPatternStep};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::batch::{Batch, RecordIndex};
use crate::protocol::boolean::random_bits_generator::RandomBitsGenerator;
use crate::protocol::boolean::{local_secret_shared_bits, BitDecomposition, BitwiseLessThan};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::mul::SecureMul;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::Replicated;
use futures::future::{try_join, try_join_all};
use std::iter::{repeat, zip};

#[allow(dead_code)]
pub async fn credit_capping<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &Batch<CreditCappingInputRow<F>>,
    cap: u32,
) -> Result<Batch<CreditCappingOutputRow<F>>, Error> {
    //
    // Step 1. Initialize two local vectors for the capping computation.
    //
    // * `final_credits` will have credit values of only source events
    //
    let mut final_credits = mask_source_credits(input, ctx.clone()).await?;

    //
    // Step 2. Compute the current_contribution for each event.
    //
    // We follow the approach used in the `AccumulateCredit` protocol. It's a
    // reversed Prefix Sum of `final_credits`.
    //
    let current_contribution =
        compute_current_contribution(ctx.clone(), input, final_credits.clone()).await?;

    //
    // 3. Compute compare_bits
    //
    // `compare_bit` = 0 if `current_contribution > cap`, or all following
    // events with the same match key has reached the cap.
    //
    let compare_bits = compute_compare_bits(ctx.clone(), &current_contribution, cap).await?;

    //
    // 4. Compute the `final_credit`
    //
    compute_final_credits(
        ctx.clone(),
        input,
        &current_contribution,
        &compare_bits,
        &mut final_credits,
        cap,
    )
    .await?;

    let output: Batch<CreditCappingOutputRow<F>> = input
        .iter()
        .enumerate()
        .map(|(i, x)| CreditCappingOutputRow {
            is_trigger_bit: input[i].is_trigger_bit.clone(),
            helper_bit: input[i].helper_bit.clone(),
            breakdown_key: x.breakdown_key.clone(),
            credit: final_credits[i].clone(),
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    Ok(output)
}

async fn mask_source_credits<F: Field>(
    input: &Batch<CreditCappingInputRow<F>>,
    ctx: SemiHonestContext<'_, F>,
) -> Result<Batch<Replicated<F>>, Error> {
    let final_credits = try_join_all(
        input
            .iter()
            .zip(zip(
                repeat(ctx.narrow(&Step::MaskSourceCredits)),
                repeat(Replicated::one(ctx.role())),
            ))
            .enumerate()
            .map(|(i, (x, (ctx, one)))| async move {
                ctx.multiply(RecordId::from(i), &x.credit, &(one - &x.is_trigger_bit))
                    .await
            }),
    )
    .await?;
    Ok(final_credits.try_into().unwrap())
}

async fn compute_current_contribution<'a, F: Field>(
    ctx: SemiHonestContext<'a, F>,
    input: &Batch<CreditCappingInputRow<F>>,
    mut current_contribution: Batch<Replicated<F>>,
) -> Result<Batch<Replicated<F>>, Error> {
    let one = Replicated::one(ctx.role());
    let mut stop_bits: Batch<Replicated<F>> = repeat(one.clone())
        .take(input.len())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    let num_rows: RecordIndex = input.len().try_into().unwrap();

    for (depth, step_size) in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let c = ctx.narrow(&InteractionPatternStep::Depth(depth));
        let mut interaction_futures = Vec::with_capacity(end as usize);

        // for each input row, create a future to execute secure multiplications
        for i in 0..end {
            let c = &c;
            let record_id = RecordId::from(i);
            let current_stop_bit = &stop_bits[i];
            let sibling_stop_bit = &stop_bits[i + step_size];
            let sibling_contribution = &current_contribution[i + step_size];
            interaction_futures.push(async move {
                // This block implements the below logic from MP-SPDZ code.
                //
                // b = stop_bit * successor.helper_bit
                // current_contribution += b * successor.current_contribution
                // stop_bit = b * successor.stop_bit

                let b = compute_b_bit(
                    c.narrow(&Step::BTimesStopBit),
                    record_id,
                    current_stop_bit,
                    &input[i + step_size].helper_bit,
                    depth == 0,
                )
                .await?;

                try_join(
                    c.narrow(&Step::CurrentContributionBTimesSuccessorCredit)
                        .multiply(record_id, &b, sibling_contribution),
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

        let results = try_join_all(interaction_futures).await?;

        // accumulate the contribution from this iteration
        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                current_contribution[i] += &credit;
                stop_bits[i] = stop_bit;
            });
    }

    Ok(current_contribution.clone())
}

async fn compute_b_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    current_stop_bit: &Replicated<F>,
    sibling_helper_bit: &Replicated<F>,
    first_iteration: bool,
) -> Result<Replicated<F>, Error> {
    // Compute `b = [this.stop_bit * sibling.helper_bit]`.
    // Since `stop_bit` is initialized with all 1's, we only multiply in
    // the second and later iterations.
    let mut b = sibling_helper_bit.clone();
    if !first_iteration {
        b = ctx
            .multiply(record_id, sibling_helper_bit, current_stop_bit)
            .await?;
    }
    Ok(b)
}

async fn compute_stop_bit<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    b_bit: &Replicated<F>,
    sibling_stop_bit: &Replicated<F>,
    first_iteration: bool,
) -> Result<Replicated<F>, Error> {
    // Since `compute_b_bit()` will always return 1 in the first found, we can
    // skip the multiplication in the first round.
    let stop_bit_future = if first_iteration {
        futures::future::Either::Left(futures::future::ok(b_bit.clone()))
    } else {
        futures::future::Either::Right(ctx.multiply(record_id, b_bit, sibling_stop_bit))
    };
    stop_bit_future.await
}

async fn compute_compare_bits<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    current_contribution: &Batch<Replicated<F>>,
    cap: u32,
) -> Result<Batch<Replicated<F>>, Error> {
    //TODO: `cap` is publicly known value for each query. We can avoid creating shares every time.
    let cap = local_secret_shared_bits(&ctx, cap.into());
    let one = Replicated::one(ctx.role());

    let random_bits_generator = RandomBitsGenerator::new();
    let compare_bits: Batch<_> = try_join_all(
        current_contribution
            .iter()
            .zip(zip(repeat(ctx.clone()), zip(repeat(cap), repeat(one))))
            .enumerate()
            .map(|(i, (credit, (ctx, (cap, one))))| {
                // The buffer inside the generator is `Arc`, so these clones
                // just increment the reference.
                let rbg = random_bits_generator.clone();
                async move {
                    let credit_bits = BitDecomposition::execute(
                        ctx.narrow(&Step::BitDecomposeCurrentContribution),
                        RecordId::from(i),
                        rbg,
                        credit,
                    )
                    .await?;

                    // compare_bit = current_contribution <=? cap
                    let compare_bit = one.clone()
                        - &BitwiseLessThan::execute(
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
    .await?
    .try_into()
    .unwrap();
    Ok(compare_bits)
}

async fn compute_final_credits<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    input: &Batch<CreditCappingInputRow<F>>,
    current_contribution: &Batch<Replicated<F>>,
    compare_bits: &Batch<Replicated<F>>,
    final_credits: &mut Batch<Replicated<F>>,
    cap: u32,
) -> Result<Batch<Replicated<F>>, Error> {
    let num_rows: RecordIndex = input.len().try_into().unwrap();
    let cap = Replicated::from_scalar(ctx.role(), F::from(cap.into()));

    // This method implements the logic from MP-SPDZ code below.
    //
    // // next line computes:
    // // if next.helper_bit==0 then d=cap <- no previous event with same match key
    // // else if next.compare_bit==0 then d=0 <- previous event used up all budget
    // // else d=cap-next.current_contribution <- use remaining budget, up to cap
    //
    // d = cap - next.helper_bit * (cap + next.compare_bit * (next.current_contribution - cap))
    //
    // // next line computes:
    // // if (compare_bit==0) then final_credit=d
    // // else final_credit=final_credit
    //
    // final_credit = d + compare_bit * (final_credit - d)

    for i in 0..(num_rows - 1) {
        let a = &current_contribution[i + 1] - &cap;
        let b = &cap
            + &ctx
                .narrow(&Step::FinalCreditsSourceContribution)
                .multiply(RecordId::from(i), &a, &compare_bits[i + 1])
                .await?;
        let c = ctx
            .narrow(&Step::FinalCreditsNextContribution)
            .multiply(RecordId::from(i), &input[i + 1].helper_bit, &b)
            .await?;
        let d = &cap - &c;

        final_credits[i] = &d
            + &ctx
                .narrow(&Step::FinalCreditsCompareBitTimesBudget)
                .multiply(
                    RecordId::from(i),
                    &compare_bits[i],
                    &(final_credits[i].clone() - &d),
                )
                .await?;
    }

    Ok(final_credits.clone())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BTimesStopBit,
    BTimesSuccessorStopBit,
    MaskSourceCredits,
    CurrentContributionBTimesSuccessorCredit,
    BitDecomposeCurrentContribution,
    IsCapLessThanCurrentContribution,
    FinalCreditsSourceContribution,
    FinalCreditsNextContribution,
    FinalCreditsCompareBitTimesBudget,
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
            Self::IsCapLessThanCurrentContribution => "is_cap_less_than_current_contribution",
            Self::FinalCreditsSourceContribution => "final_credits_source_contribution",
            Self::FinalCreditsNextContribution => "final_credits_next_contribution",
            Self::FinalCreditsCompareBitTimesBudget => "final_credits_compare_bit_times_budget",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::generate_shared_input;
    use crate::{
        ff::{Field, Fp32BitPrime},
        protocol::attribution::credit_capping::credit_capping,
        protocol::QueryId,
        test_fixture::{Reconstruct, TestWorld},
    };
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    const S: u128 = 0;
    const T: u128 = 1;
    const H: [u128; 2] = [0, 1];
    const BD: [u128; 8] = [0, 1, 2, 3, 4, 5, 6, 7];

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
        let world = TestWorld::new(QueryId);
        let context = world.contexts::<Fp32BitPrime>();
        let mut rng = StepRng::new(100, 1);

        let shares = generate_shared_input(TEST_CASE, &mut rng);

        let [c0, c1, c2] = context;
        let [s0, s1, s2] = shares;

        let h0_future = credit_capping(c0, &s0, CAP);
        let h1_future = credit_capping(c1, &s1, CAP);
        let h2_future = credit_capping(c2, &s2, CAP);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

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
