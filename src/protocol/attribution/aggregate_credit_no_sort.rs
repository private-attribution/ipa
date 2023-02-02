use super::{
    if_else,
    input::{MCAggregateCreditInputRow, MCAggregateCreditOutputRow},
};
use crate::bits::BitArray;
use crate::error::Error;
use crate::ff::Field;
use crate::protocol::boolean::bitwise_equal::bitwise_equal_constant;
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::{BitOpStep, RecordId, Substep};
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
#[allow(dead_code)]
pub async fn aggregate_credit<F: Field, BK: BitArray>(
    ctx: SemiHonestContext<'_, F>,
    capped_credits: &[MCAggregateCreditInputRow<F>],
    max_breakdown_key: u128,
) -> Result<Vec<MCAggregateCreditOutputRow<F>>, Error> {
    let zero = Replicated::ZERO;
    let one = ctx.share_of_one();

    let mut aggregated_credits = (0..max_breakdown_key)
        .map(|i| {
            // Since these breakdown keys are publicly known, we can directly convert them to Vec<Replicated<F>>
            let bk_bits = BK::truncate_from(i);
            let converted_bk = (0..BK::BITS)
                .map(|i| {
                    if bk_bits[i] {
                        one.clone()
                    } else {
                        zero.clone()
                    }
                })
                .collect::<Vec<_>>();

            MCAggregateCreditOutputRow {
                breakdown_key: converted_bk,
                credit: zero.clone(),
            }
        })
        .collect::<Vec<_>>();

    let bitwise_eq_ctx = ctx
        .narrow(&Step::BitwiseEqualBreakdownKey)
        .set_total_records(capped_credits.len());
    let if_else_ctx = ctx
        .narrow(&Step::BreakdownKeyIfElse)
        .set_total_records(capped_credits.len());
    for (i, row) in capped_credits.iter().enumerate() {
        for bk in 0..max_breakdown_key {
            let bk_index = usize::try_from(bk).unwrap();
            let record_id = RecordId::from(i);

            let is_bk_equal = bitwise_equal_constant(
                bitwise_eq_ctx.narrow(&BitOpStep::from(bk_index)),
                record_id,
                &row.breakdown_key,
                bk,
            )
            .await?;

            aggregated_credits[bk_index].credit += &if_else(
                if_else_ctx.narrow(&BitOpStep::from(bk_index)),
                record_id,
                &is_bk_equal,
                &row.credit,
                &zero,
            )
            .await?;
        }
    }

    Ok(aggregated_credits)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    BitwiseEqualBreakdownKey,
    BreakdownKeyIfElse,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::BitwiseEqualBreakdownKey => "bitwise_equal_breakdown_key",
            Self::BreakdownKeyIfElse => "breakdown_key_if_else",
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::aggregate_credit;
    use crate::aggregation_test_input;
    use crate::bits::BitArray;
    use crate::ff::{Field, Fp32BitPrime};
    use crate::protocol::attribution::input::{AggregateCreditInputRow, MCAggregateCreditInputRow};
    use crate::protocol::context::Context;
    use crate::protocol::modulus_conversion::{
        combine_slices, convert_all_bits, convert_all_bits_local,
    };
    use crate::protocol::{BreakdownKey, MatchKey};
    use crate::secret_sharing::SharedValue;
    use crate::test_fixture::input::GenericReportTestInput;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};

    #[tokio::test]
    pub async fn aggregate() {
        const MAX_BREAKDOWN_KEY: u128 = 8;
        const NUM_MULTI_BITS: u32 = 3;

        const EXPECTED: &[[u128; 2]] = &[
            // breakdown_key, credit
            [0, 0],
            [1, 0],
            [2, 12],
            [3, 0],
            [4, 18],
            [5, 6],
            [6, 0],
            [7, 0],
        ];

        let input: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = aggregation_test_input!(
            [
                { helper_bit: 0, breakdown_key: 3, credit: 0 },
                { helper_bit: 0, breakdown_key: 4, credit: 0 },
                { helper_bit: 1, breakdown_key: 4, credit: 18 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 0, breakdown_key: 1, credit: 0 },
                { helper_bit: 0, breakdown_key: 0, credit: 0 },
                { helper_bit: 0, breakdown_key: 2, credit: 2 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 2, credit: 0 },
                { helper_bit: 1, breakdown_key: 2, credit: 10 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
                { helper_bit: 1, breakdown_key: 5, credit: 6 },
                { helper_bit: 1, breakdown_key: 0, credit: 0 },
            ];
            (Fp32BitPrime, MatchKey, BreakdownKey)
        );

        let world = TestWorld::new().await;
        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(
                input,
                |ctx, input: Vec<AggregateCreditInputRow<Fp32BitPrime, BreakdownKey>>| async move {
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
                        combine_slices(&converted_bk_shares, BreakdownKey::BITS);
                    let modulus_converted_shares: Vec<_> = input
                        .iter()
                        .zip(converted_bk_shares)
                        .map(|(row, bk)| MCAggregateCreditInputRow {
                            breakdown_key: bk,
                            credit: row.credit.clone(),
                        })
                        .collect();

                    aggregate_credit::<Fp32BitPrime, BreakdownKey>(
                        ctx,
                        &modulus_converted_shares,
                        MAX_BREAKDOWN_KEY,
                    )
                    .await
                    .unwrap()
                },
            )
            .await
            .reconstruct();

        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    result[i].breakdown_key.as_u128(),
                    result[i].trigger_value.as_u128()
                ]
            );
        }
    }
}
