use super::{CreditCappingInputRow, CreditCappingOutputRow, InteractionPatternInputRow};
use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Role;
use crate::protocol::batch::{Batch, RecordIndex};
use crate::protocol::boolean::{local_secret_shared_bits, BitDecomposition, BitwiseLessThan};
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::mul::SecureMul;
use crate::protocol::reveal::Reveal;
use crate::protocol::{IterStep, RecordId, Substep};
use crate::secret_sharing::Replicated;
use futures::future::{try_join, try_join_all};
use futures::Future;
use std::iter::{repeat, zip};

async fn debug_value<F: Field>(
    msg: &str,
    v: &Replicated<F>,
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
) -> Result<(), Error> {
    let s = ctx.clone().reveal(record_id, v).await.unwrap();
    if ctx.role() == Role::H1 {
        println!("{}{}", msg, s.as_u128());
    }
    Ok(())
}

pub struct CreditCapping {}

impl CreditCapping {
    #[allow(dead_code)]
    pub async fn execute<F: Field>(
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
        let mut final_credits = Self::mask_source_credits(input, ctx.clone()).await?;

        // for (i, x) in final_credits.iter().enumerate() {
        //     debug_value(
        //         &format!("final_credits({}): ", i),
        //         x,
        //         ctx.clone(),
        //         RecordId::from(i),
        //     )
        //     .await?;
        // }

        //
        // Step 2. Compute the current_contribution for each event.
        //
        // We follow the approach used in the `AccumulateCredit` protocol.
        // `current_contribution`
        //
        let current_contribution = Self::compute_current_contribution(
            ctx.clone(),
            input,
            stop_bits.clone(),
            final_credits.clone(),
        )
        .await?;

        // for (i, x) in current_contribution.iter().enumerate() {
        //     debug_value(
        //         &format!("current_contribution({}): ", i),
        //         x,
        //         ctx.clone(),
        //         RecordId::from(i),
        //     )
        //     .await?;
        // }

        //
        // 3. Compute compare_bits
        //
        // `compare_bit` = 0 if `current_contribution > cap`, or all following
        // events with the same match key has reached the cap.
        //
        let compare_bits = Self::compute_compare_bits(
            ctx.clone(),
            input,
            stop_bits.clone(),
            &current_contribution,
            cap,
        )
        .await?;

        for (i, x) in compare_bits.iter().enumerate() {
            debug_value(
                &format!("compare_bits({}): ", i),
                x,
                ctx.clone(),
                RecordId::from(i),
            )
            .await?;
        }

        //
        // 4. Compute the `final_credit`
        //
        Self::compute_final_credits(
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
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = input.len() as RecordIndex;

        let mut iteration_step = IterStep::new("current_contribution_iteration", 0);
        for step_size in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
        {
            let end = num_rows - step_size;
            let mut interaction_futures = Vec::with_capacity(end as usize);

            let c = ctx.narrow(iteration_step.next());
            let mut interaction_step = IterStep::new("current_contribution_interaction", 0);

            // for each input row, create a future to execute secure multiplications
            for i in 0..end {
                let current = InteractionPatternInputRow {
                    is_trigger_bit: input[i].is_trigger_bit.clone(),
                    helper_bit: input[i].helper_bit.clone(),
                    stop_bit: stop_bits[i].clone(),
                    interaction_bit: current_contribution[i].clone(),
                };
                let successor = InteractionPatternInputRow {
                    is_trigger_bit: input[i + step_size].is_trigger_bit.clone(),
                    helper_bit: input[i + step_size].helper_bit.clone(),
                    stop_bit: stop_bits[i + step_size].clone(),
                    interaction_bit: current_contribution[i + step_size].clone(),
                };

                interaction_futures.push(Self::interaction_pattern(
                    c.narrow(interaction_step.next()),
                    RecordId::from(0_u32),
                    current,
                    successor,
                    |ctx, record_id, b, _current, successor| async move {
                        ctx.narrow(&Step::CurrentContributionBTimesSuccessorCredit)
                            .multiply(record_id, &b, &successor)
                            .await
                    },
                    iteration_step.is_first_iteration(),
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
        input: &Batch<CreditCappingInputRow<F>>,
        stop_bits: Batch<Replicated<F>>,
        current_contribution: &Batch<Replicated<F>>,
        cap: u32,
    ) -> Result<Batch<Replicated<F>>, Error> {
        let cap = local_secret_shared_bits(cap.into(), ctx.role());
        let one = Replicated::one(ctx.role());
        let mut compare_bits: Batch<_> = try_join_all(
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

        let mut stop_bits = stop_bits;
        #[allow(clippy::cast_possible_truncation)]
        let num_rows = input.len() as RecordIndex;

        let mut iteration_step = IterStep::new("compare_bits_iteration", 0);
        for step_size in std::iter::successors(Some(1u32), |prev| prev.checked_mul(2))
            .take_while(|&v| v < num_rows)
        {
            let mut interaction_futures = Vec::with_capacity((num_rows - step_size) as usize);

            let c = ctx.narrow(iteration_step.next());
            let mut interaction_step = IterStep::new("compare_bits_interaction", 0);

            // for each input row, create a future to execute secure multiplications
            // this is the "reverse interaction" pattern
            for i in step_size..num_rows {
                let current = InteractionPatternInputRow {
                    is_trigger_bit: input[i].is_trigger_bit.clone(),
                    helper_bit: input[i].helper_bit.clone(),
                    stop_bit: stop_bits[i].clone(),
                    interaction_bit: compare_bits[i].clone(),
                };
                let predecessor = InteractionPatternInputRow {
                    is_trigger_bit: input[i - step_size].is_trigger_bit.clone(),
                    helper_bit: input[i - step_size].helper_bit.clone(),
                    stop_bit: stop_bits[i - step_size].clone(),
                    interaction_bit: compare_bits[i - step_size].clone(),
                };

                interaction_futures.push(Self::interaction_pattern(
                    c.narrow(interaction_step.next()),
                    RecordId::from(0_u32),
                    current,
                    predecessor,
                    |ctx, record_id, b, current, predecessor| async move {
                        let x = ctx
                            .narrow(&Step::CompareBitsCompareBitTimesCompareBit)
                            .multiply(
                                record_id,
                                &current,
                                &(predecessor - &Replicated::one(ctx.role())),
                            )
                            .await?;
                        ctx.narrow(&Step::CompareBitsBTimesCompareBit)
                            .multiply(record_id, &b, &x)
                            .await
                    },
                    iteration_step.is_first_iteration(),
                ));
            }

            let results = try_join_all(interaction_futures).await?;

            // This is a reversed interaction pattern, so the `results[0..i]`
            // are actually the results for `step_size..num_rows`.
            //
            // !!! This code is not in MP-SPDZ prototype !!!
            //
            (step_size..num_rows)
                .zip(results)
                .for_each(|(i, (compare_bit, stop_bit))| {
                    compare_bits[i] = &compare_bits[i] + &compare_bit;
                    stop_bits[i] = stop_bit;
                });
        }

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

        for i in 0..(num_rows - 1) {
            let a = cap.clone() - &current_contribution[i + 1].clone();
            let b = cap.clone()
                + &ctx
                    .narrow(&Step::FinalCreditsSourceContribution)
                    .multiply(RecordId::from(i), &compare_bits[i + 1].clone(), &a)
                    .await?;
            let c = ctx
                .narrow(&Step::FinalCreditsNextContribution)
                .multiply(RecordId::from(i), &input[i + 1].helper_bit, &b)
                .await?;
            let d = cap.clone() - &c;

            final_credits[i + 1] = d.clone()
                + &ctx
                    .narrow(&Step::FinalCreditsCompareBitTimesBudget)
                    .multiply(
                        RecordId::from(i),
                        &compare_bits[i + 1],
                        &(final_credits[i + 1].clone() - &d),
                    )
                    .await?;
        }

        // for i in 1..num_rows {
        //     let a = cap.clone() - &current_contribution[i - 1].clone();
        //     let b = cap.clone()
        //         + &ctx
        //             .narrow(&Step::FinalCreditsSourceContribution)
        //             .multiply(RecordId::from(i - 1), &compare_bits[i - 1].clone(), &a)
        //             .await?;
        //     let c = ctx
        //         .narrow(&Step::FinalCreditsNextContribution)
        //         .multiply(RecordId::from(i - 1), &input[i - 1].helper_bit, &b)
        //         .await?;
        //     let d = cap.clone() - &c;

        //     // final_credits[i] = d.clone()
        //     final_credits[i] = d.clone()
        //         + &ctx
        //             .narrow(&Step::FinalCreditsCompareBitTimesBudget)
        //             .multiply(
        //                 RecordId::from(i - 1),
        //                 // &compare_bits[i],
        //                 // &(final_credits[i].clone() - &d),
        //                 &compare_bits[i - 1],
        //                 &(final_credits[i - 1].clone() - &d),
        //             )
        //             .await?;
        // }

        Ok(final_credits.clone())
    }

    async fn interaction_pattern<'a, F, H, R>(
        ctx: SemiHonestContext<'a, F>,
        record_id: RecordId,
        this: InteractionPatternInputRow<F>,
        other: InteractionPatternInputRow<F>,
        mut interaction_fn: H,
        first_iteration: bool,
    ) -> Result<(Replicated<F>, Replicated<F>), Error>
    where
        F: Field,
        H: FnMut(
            SemiHonestContext<'a, F>,
            RecordId,
            Replicated<F>,
            Replicated<F>,
            Replicated<F>,
        ) -> R,
        R: Future<Output = Result<Replicated<F>, Error>> + Send,
    {
        // Compute `b = [this.stop_bit * other.helper_bit]`.
        // Since `stop_bit` is initialized with all 1's, we only multiply in
        // the second and later iterations.
        let mut b = other.helper_bit;
        if !first_iteration {
            b = ctx
                .narrow(&Step::BTimesStopBit)
                .multiply(record_id, &b, &this.stop_bit)
                .await?;
        }

        let interaction_future = interaction_fn(
            ctx.clone(),
            record_id,
            b.clone(),
            this.interaction_bit.clone(),
            other.interaction_bit.clone(),
        );

        // For the same reason as calculating [b], we skip the multiplication
        // in the first iteration.
        let stop_bit_future = if first_iteration {
            futures::future::Either::Left(futures::future::ok(b.clone()))
        } else {
            futures::future::Either::Right(ctx.narrow(&Step::BTimesSuccessorStopBit).multiply(
                record_id,
                &b,
                &other.stop_bit,
            ))
        };

        try_join(interaction_future, stop_bit_future).await
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BTimesStopBit,
    BTimesSuccessorStopBit,
    MaskSourceCredits,
    CurrentContributionBTimesSuccessorCredit,
    BitDecomposeCurrentContribution,
    IsCapLessThanCurrentContribution,
    CompareBitsCompareBitTimesCompareBit,
    CompareBitsBTimesCompareBit,
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
            Self::CompareBitsCompareBitTimesCompareBit => {
                "compare_bits_compare_bit_times_compare_bit"
            }
            Self::CompareBitsBTimesCompareBit => "compare_bits_b_times_compare_bit",
            Self::FinalCreditsSourceContribution => "final_credits_source_contribution",
            Self::FinalCreditsNextContribution => "final_credits_next_contribution",
            Self::FinalCreditsCompareBitTimesBudget => "final_credits_compare_bit_times_budget",
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        protocol::attribution::credit_capping::CreditCapping,
        protocol::batch::Batch,
        protocol::{attribution::AttributionInputRow, QueryId},
        test_fixture::{share, Reconstruct, TestWorld},
    };
    use rand::rngs::mock::StepRng;
    use std::iter::zip;
    use tokio::try_join;

    fn generate_shared_input(
        input: &[[u128; 4]],
        rng: &mut StepRng,
    ) -> [Batch<AttributionInputRow<Fp31>>; 3] {
        let num_rows = input.len();
        let mut shares = [
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
            Vec::with_capacity(num_rows),
        ];

        for x in input {
            let itb = share(Fp31::from(x[0]), rng);
            let hb = share(Fp31::from(x[1]), rng);
            let bk = share(Fp31::from(x[2]), rng);
            let val = share(Fp31::from(x[3]), rng);
            for (i, ((itb, hb), (bk, val))) in zip(zip(itb, hb), zip(bk, val)).enumerate() {
                shares[i].push(AttributionInputRow {
                    is_trigger_bit: itb,
                    helper_bit: hb,
                    breakdown_key: bk,
                    credit: val,
                });
            }
        }

        assert_eq!(shares[0].len(), shares[1].len());
        assert_eq!(shares[1].len(), shares[2].len());

        [
            Batch::try_from(shares[0].clone()).unwrap(),
            Batch::try_from(shares[1].clone()).unwrap(),
            Batch::try_from(shares[2].clone()).unwrap(),
        ]
    }

    #[tokio::test]
    pub async fn cap() {
        // a result output from `AccumulateCredit`
        const RAW_INPUT: &[[u128; 4]; 17] = &[
            // [is_trigger, helper_bit, breakdown_key, credit]
            [0, 0, 3, 0],
            [0, 0, 4, 0],
            [0, 1, 4, 19],
            [1, 1, 0, 19],
            [1, 1, 0, 9],
            [1, 1, 0, 7],
            [1, 1, 0, 6],
            [1, 1, 0, 1],
            [0, 0, 1, 0],
            [1, 0, 0, 10],
            [0, 0, 2, 15],
            [1, 1, 0, 15],
            [1, 1, 0, 12],
            [0, 1, 2, 0],
            [0, 1, 2, 10],
            [1, 1, 0, 10],
            [1, 1, 0, 4],
        ];
        const CAP: u32 = 20;
        const EXPECTED: &[u128] = &[0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 10, 0, 0, 0, 0, 0, 0];

        let world = TestWorld::<Fp31>::new(QueryId);
        let context = world.contexts();
        let mut rng = StepRng::new(100, 1);

        let shares = generate_shared_input(RAW_INPUT, &mut rng);

        let [c0, c1, c2] = context;
        let [s0, s1, s2] = shares;

        let h0_future = CreditCapping::execute(c0, &s0, CAP);
        let h1_future = CreditCapping::execute(c1, &s1, CAP);
        let h2_future = CreditCapping::execute(c2, &s2, CAP);

        let result = try_join!(h0_future, h1_future, h2_future).unwrap();

        assert_eq!(result.0.len(), RAW_INPUT.len());
        assert_eq!(result.1.len(), RAW_INPUT.len());
        assert_eq!(result.2.len(), RAW_INPUT.len());

        for (i, expected) in EXPECTED.iter().enumerate() {
            let v = (
                &result.0[i].credit,
                &result.1[i].credit,
                &result.2[i].credit,
            )
                .reconstruct();
            // assert_eq!(v.as_u128(), *expected);
            println!("{:?} ", v.as_u128());
        }
    }
}
