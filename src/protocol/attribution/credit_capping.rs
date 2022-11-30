use super::{
    CreditCappingInputRow, CreditCappingOutputRow, InteractionPatternInputRow,
    InteractionPatternStep,
};
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::batch::{Batch, RecordIndex};
use crate::protocol::boolean::{local_secret_shared_bits, BitDecomposition, BitwiseLessThan};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::mul::SecureMul;
use crate::protocol::{RecordId, Substep};
use crate::secret_sharing::Replicated;
use futures::future::{try_join, try_join_all};
use futures::Future;
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
    // * `stop_bits` is used to determine when to stop the computation
    // * `final_credits` will have credit values of only source events
    //
    let one = Replicated::one(ctx.role());
    let stop_bits: Batch<Replicated<F>> = repeat(one.clone())
        .take(input.len())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let mut final_credits = mask_source_credits(input, ctx.clone()).await?;

    //
    // Step 2. Compute the current_contribution for each event.
    //
    // We follow the approach used in the `AccumulateCredit` protocol.
    // `current_contribution`
    //
    let current_contribution =
        compute_current_contribution(ctx.clone(), input, stop_bits.clone(), final_credits.clone())
            .await?;

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
    stop_bits: Batch<Replicated<F>>,
    current_contribution: Batch<Replicated<F>>,
) -> Result<Batch<Replicated<F>>, Error> {
    let mut stop_bits = stop_bits;
    let mut current_contribution = current_contribution;
    let num_rows: RecordIndex = input.len().try_into().unwrap();

    // Below is the logic from MP-SPDZ prototype, which this part of the
    // protocol implements.
    //
    // b = stop_bit * successor.helper_bit
    // current_contribution += b * successor.current_contribution
    // stop_bit = b * successor.stop_bit

    for (depth, step_size) in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
        .take_while(|&v| v < num_rows)
        .enumerate()
    {
        let end = num_rows - step_size;
        let mut interaction_futures = Vec::with_capacity(end as usize);

        let c = ctx.narrow(&InteractionPatternStep::Depth(depth));

        // for each input row, create a future to execute secure multiplications
        for i in 0..end {
            let current = InteractionPatternInputRow {
                is_trigger_bit: input[i].is_trigger_bit.clone(),
                helper_bit: input[i].helper_bit.clone(),
                stop_bit: stop_bits[i].clone(),
                interaction_value: current_contribution[i].clone(),
            };
            let successor = InteractionPatternInputRow {
                is_trigger_bit: input[i + step_size].is_trigger_bit.clone(),
                helper_bit: input[i + step_size].helper_bit.clone(),
                stop_bit: stop_bits[i + step_size].clone(),
                interaction_value: current_contribution[i + step_size].clone(),
            };

            interaction_futures.push(interaction_pattern(
                c.clone(),
                RecordId::from(i),
                current,
                successor,
                |ctx, record_id, input| async move {
                    ctx.narrow(&Step::CurrentContributionBTimesSuccessorCredit)
                        .multiply(record_id, &input.b, &input.sibling)
                        .await
                },
                depth == 0,
            ));
        }

        let results = try_join_all(interaction_futures).await?;

        // accumulate the contribution from this iteration
        results
            .into_iter()
            .enumerate()
            .for_each(|(i, (credit, stop_bit))| {
                current_contribution[i] = &current_contribution[i] + &credit;
                stop_bits[i] = stop_bit;
            });
    }

    Ok(current_contribution.clone())
}

async fn compute_compare_bits<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    current_contribution: &Batch<Replicated<F>>,
    cap: u32,
) -> Result<Batch<Replicated<F>>, Error> {
    //TODO: `cap` is publicly known value for each query. We can avoid creating shares every time.
    let cap = local_secret_shared_bits(cap.into(), ctx.role());
    let one = Replicated::one(ctx.role());
    let compare_bits: Batch<_> = try_join_all(
        current_contribution
            .iter()
            .zip(zip(repeat(ctx.clone()), zip(repeat(cap), repeat(one))))
            .enumerate()
            .map(|(i, (contrib, (ctx, (cap, one))))| async move {
                let contrib_b = BitDecomposition::execute(
                    ctx.narrow(&Step::BitDecomposeCurrentContribution),
                    RecordId::from(i),
                    contrib,
                )
                .await?;
                let lt_b = one.clone()
                    - &BitwiseLessThan::execute(
                        ctx.narrow(&Step::IsCapLessThanCurrentContribution),
                        RecordId::from(i),
                        &cap,
                        &contrib_b,
                    )
                    .await?;
                Ok::<_, Error>(lt_b)
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
    #[allow(clippy::cast_possible_truncation)]
    let num_rows = input.len() as RecordIndex;
    let cap = Replicated::from_scalar(ctx.role(), F::from(cap.into()));

    // Below is the logic from MP-SPDZ prototype, which this part of the
    // protocol implements.
    //
    // // next line computes:
    // //
    // // if next.helper_bit==0 then d=cap <-no previous event with same match key
    // // else if next.compare_bit==0 then d=0 <-previous event used up all budget
    // //      else d=cap-next.current_contribution <-use remaining budget, up to cap
    //
    // d = cap - next.helper_bit * (cap + next.compare_bit * (next.current_contribution-cap))
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

#[allow(dead_code)]
struct InteractionClosureInput<F: Field> {
    b: Replicated<F>,
    current: Replicated<F>,
    sibling: Replicated<F>,
}

/// Many attribution protocols use interaction patterns to obliviously
/// compute values, and they usually follow the same pattern. This is a
/// generalized logic of the "interaction pattern" computation.
///
/// `interaction_fn` is the computation unique to each protocol. The caller
/// will use five parameters given as closure's parameters, which are:
///
/// * context
/// * record ID
/// * `b` bit
/// * current `interaction_value`
/// * sibling `interaction_value`
///
/// The latter three are contained in `InteractionClosureInput` struct.
async fn interaction_pattern<'a, F, H, R>(
    ctx: SemiHonestContext<'a, F>,
    record_id: RecordId,
    this: InteractionPatternInputRow<F>,
    sibling: InteractionPatternInputRow<F>,
    mut interaction_fn: H,
    first_iteration: bool,
) -> Result<(Replicated<F>, Replicated<F>), Error>
where
    F: Field,
    H: FnMut(SemiHonestContext<'a, F>, RecordId, InteractionClosureInput<F>) -> R,
    R: Future<Output = Result<Replicated<F>, Error>> + Send,
{
    // Compute `b = [this.stop_bit * sibling.helper_bit]`.
    // Since `stop_bit` is initialized with all 1's, we only multiply in
    // the second and later iterations.
    let mut b = sibling.helper_bit;
    if !first_iteration {
        b = ctx
            .narrow(&Step::BTimesStopBit)
            .multiply(record_id, &b, &this.stop_bit)
            .await?;
    }

    let interaction_future = interaction_fn(
        ctx.clone(),
        record_id,
        InteractionClosureInput {
            b: b.clone(),
            current: this.interaction_value.clone(),
            sibling: sibling.interaction_value.clone(),
        },
    );

    // For the same reason as calculating [b], we skip the multiplication
    // in the first iteration.
    let stop_bit_future = if first_iteration {
        futures::future::Either::Left(futures::future::ok(b.clone()))
    } else {
        futures::future::Either::Right(ctx.narrow(&Step::BTimesSuccessorStopBit).multiply(
            record_id,
            &b,
            &sibling.stop_bit,
        ))
    };

    try_join(interaction_future, stop_bit_future).await
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
        let world = TestWorld::<Fp32BitPrime>::new(QueryId);
        let context = world.contexts();
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
