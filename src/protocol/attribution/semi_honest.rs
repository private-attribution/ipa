use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::aggregate_credit,
    credit_capping::credit_capping,
    input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
};
use crate::{
    error::Error,
    ff::{GaloisField, PrimeField, Serializable},
    protocol::{
        boolean::{equality_test, random_bits_generator::RandomBitsGenerator},
        context::{Context, SemiHonestContext},
        ipa::IPAModulusConvertedInputRow,
        RecordId, Substep,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare,
};
use futures::future::try_join_all;
use std::iter::zip;

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<F, BK>(
    ctx: SemiHonestContext<'_>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BK>>, Error>
where
    F: PrimeField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
{
    let eq_test_ctx = ctx
        .narrow(&Step::ComputeHelperBits)
        .set_total_records(sorted_rows.len() - 1);

    let rbg = RandomBitsGenerator::new(ctx.clone());

    let futures = sorted_rows
        .iter()
        .zip(sorted_rows.iter().skip(1))
        .enumerate()
        .map(|(i, (row, next_row))| {
            let record_id = RecordId::from(i);
            let c = eq_test_ctx.clone();
            let rbg_ref = &rbg;
            async move {
                equality_test(c, record_id, rbg_ref, &row.mk_shares, &next_row.mk_shares).await
            }
        });
    let helper_bits = Some(AdditiveShare::ZERO)
        .into_iter()
        .chain(try_join_all(futures).await?);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| {
            MCAccumulateCreditInputRow::new(
                row.is_trigger_bit,
                hb,
                row.breakdown_key,
                row.trigger_value,
            )
        })
        .collect::<Vec<_>>();

    let accumulated_credits = accumulate_credit(
        ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
        per_user_credit_cap,
    )
    .await?;

    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    aggregate_credit::<F, BK>(
        ctx.narrow(&Step::AggregateCredit),
        user_capped_credits.into_iter(),
        max_breakdown_key,
        num_multi_bits,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
    Debug,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
            Self::Debug => "debug",
        }
    }
}
