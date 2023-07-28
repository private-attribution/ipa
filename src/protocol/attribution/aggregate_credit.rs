extern crate ipa_macros;

use crate::{
    error::Error,
    ff::{GaloisField, Gf2, PrimeField, Serializable},
    protocol::{
        attribution::input::{MCAggregateCreditInputRow, MCAggregateCreditOutputRow},
        basics::ZeroPositions,
        context::{UpgradableContext, UpgradedContext, Validator},
        modulus_conversion::{convert_bit, convert_bit_local},
        sort::{check_everything, generate_permutation::ShuffledPermutationWrapper},
        step::BitOpStep,
        BasicProtocols, RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
        },
        BitDecomposed, Linear as LinearSecretSharing,
    },
};
use ipa_macros::step;
use strum::AsRefStr;

/// This is the number of breakdown keys above which it is more efficient to SORT by breakdown key.
/// Below this number, it's more efficient to just do a ton of equality checks.
/// This number was determined empirically on 27 Feb 2023
const SIMPLE_AGGREGATION_BREAK_EVEN_POINT: u32 = 32;

/// Aggregation step for Oblivious Attribution protocol.
/// # Panics
/// It probably won't
///
/// # Errors
/// propagates errors from multiplications
#[tracing::instrument(name = "aggregate_credit", skip_all)]
// instrumenting this function makes the return type look bad to Clippy
#[allow(clippy::type_complexity)]
pub async fn aggregate_credit<C, V, F, BK, I, S>(
    validator: V,
    capped_credits: I,
    max_breakdown_key: u32,
) -> Result<(V, Vec<MCAggregateCreditOutputRow<F, S, BK>>), Error>
where
    C: UpgradableContext<Validator<F> = V>,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    V: Validator<C, F>,
    F: PrimeField + ExtendableField,
    BK: GaloisField,
    I: Iterator<Item = MCAggregateCreditInputRow<F, S>> + ExactSizeIterator + Send,
    S: LinearSecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F> + Serializable + 'static,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
{
    let m_ctx = validator.context();

    if max_breakdown_key <= SIMPLE_AGGREGATION_BREAK_EVEN_POINT {
        let res = simple_aggregate_credit(m_ctx, capped_credits, max_breakdown_key).await?;
        Ok((validator, res))
    } else {
        Err(Error::Unsupported(
            format!("query uses {max_breakdown_key} breakdown keys; only {SIMPLE_AGGREGATION_BREAK_EVEN_POINT} are supported")
        ))
    }
}

async fn simple_aggregate_credit<F, C, I, T, BK>(
    ctx: C,
    capped_credits: I,
    max_breakdown_key: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, T, BK>>, Error>
where
    F: PrimeField,
    I: Iterator<Item = MCAggregateCreditInputRow<F, T>> + ExactSizeIterator + Send,
    C: UpgradedContext<F, Share = T>,
    T: LinearSecretSharing<F> + BasicProtocols<C, F> + Serializable + 'static,
    BK: GaloisField,
{
    let mut sums = vec![T::ZERO; max_breakdown_key as usize];
    let to_take = usize::try_from(max_breakdown_key).unwrap();
    let valid_bits_count = (u32::BITS - (max_breakdown_key - 1).leading_zeros()) as usize;

    let equality_check_context = ctx
        .narrow(&Step::ComputeEqualityChecks)
        .set_total_records(capped_credits.len());
    let check_times_credit_context = ctx
        .narrow(&Step::CheckTimesCredit)
        .set_total_records(capped_credits.len());
    let mod_conv_context = ctx
        .narrow(&Step::ModConvBreakdownKeyBits)
        .set_total_records(capped_credits.len());
    let upgrade_context = ctx
        .narrow(&Step::UpgradeBreakdownKeyBits)
        .set_total_records(capped_credits.len());

    let increments = ctx
        .try_join(capped_credits.enumerate().map(|(i, row)| {
            let c1 = equality_check_context.clone();
            let c2 = check_times_credit_context.clone();
            let c3 = mod_conv_context.clone();
            let c4 = upgrade_context.clone();
            let helper_role = c1.role();
            let bd_key = &row.breakdown_key[..valid_bits_count];
            let local_bit_lists = bd_key
                .iter()
                .map(|bit| convert_bit_local::<F, Gf2>(helper_role, 0, bit))
                .collect::<Vec<_>>();
            async move {
                let mod_conv_breakdown_key_bits: Vec<Replicated<F>> =
                    c1.try_join(local_bit_lists.iter().enumerate().map(
                        |(bit_index, bit_triple)| {
                            let step = BitOpStep::from(bit_index);
                            let c = c3.narrow(&step);
                            async move {
                                let record_id = RecordId::from(i);
                                convert_bit(c, record_id, bit_triple).await
                            }
                        },
                    ))
                    .await?;

                let upgraded_mod_conv_breakdown_key_bits = c4
                    .try_join(mod_conv_breakdown_key_bits.into_iter().enumerate().map(
                        |(bit_index, bit)| {
                            let step = BitOpStep::from(bit_index);
                            let c = c4.narrow(&step);
                            async move {
                                let record_id = RecordId::from(i);
                                c.upgrade_one(record_id, bit, ZeroPositions::Pvvv).await
                            }
                        },
                    ))
                    .await?;

                let equality_checks =
                    check_everything(c1.clone(), i, &upgraded_mod_conv_breakdown_key_bits).await?;
                c1.try_join(equality_checks.iter().take(to_take).enumerate().map(
                    |(check_idx, check)| {
                        let credit = &row.credit;
                        let step = BitOpStep::from(check_idx);
                        let c = c2.narrow(&step);
                        let record_id = RecordId::from(i);
                        async move { check.multiply(credit, c, record_id).await }
                    },
                ))
                .await
            }
        }))
        .await?;
    for increments_for_row in increments {
        for (i, increment) in increments_for_row.iter().enumerate() {
            sums[i] += increment;
        }
    }

    let zero = T::ZERO;
    let one = T::share_known_value(&ctx, F::ONE);

    Ok(sums
        .into_iter()
        .enumerate()
        .map(|(i, sum)| {
            let breakdown_key = u128::try_from(i).unwrap();
            let bk_bits = BK::truncate_from(breakdown_key);
            let converted_bk = BitDecomposed::decompose(BK::BITS, |i| {
                if bk_bits[i] {
                    one.clone()
                } else {
                    zero.clone()
                }
            });

            MCAggregateCreditOutputRow::new(converted_bk, sum)
        })
        .collect())
}

#[step]
pub(crate) enum Step {
    ComputeEqualityChecks,
    CheckTimesCredit,
    ModConvBreakdownKeyBits,
    UpgradeBreakdownKeyBits,
}

#[cfg(all(test, unit_test))]
mod tests {

    use super::aggregate_credit;
    use crate::{
        aggregation_test_input,
        ff::{Field, Fp32BitPrime, GaloisField},
        protocol::{
            attribution::input::{AggregateCreditInputRow, MCAggregateCreditInputRow},
            context::{Context, UpgradableContext},
            modulus_conversion::{convert_all_bits, convert_all_bits_local},
            BreakdownKey, MatchKey,
        },
        secret_sharing::SharedValue,
        test_fixture::{input::GenericReportTestInput, Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn aggregate() {
        const MAX_BREAKDOWN_KEY: u32 = 8;

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

        let world = TestWorld::default();
        let result: Vec<GenericReportTestInput<Fp32BitPrime, MatchKey, BreakdownKey>> = world
            .semi_honest(
                input.into_iter(),
                |ctx, input: Vec<AggregateCreditInputRow<Fp32BitPrime, BreakdownKey>>| async move {
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
                        .map(|(row, bk)| MCAggregateCreditInputRow::new(bk, row.credit.clone()));

                    let (_validator, output) = aggregate_credit(
                        ctx.clone().validator(), // note: not upgrading any inputs, so semi-honest only.
                        modulus_converted_shares,
                        MAX_BREAKDOWN_KEY,
                    )
                    .await
                    .unwrap();
                    output
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
