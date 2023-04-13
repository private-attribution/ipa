use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::aggregate_credit,
    apply_attribution_window::apply_attribution_window,
    compute_helper_bits_gf2, compute_stop_bits,
    credit_capping::credit_capping,
    input::{MCAggregateCreditOutputRow, MCApplyAttributionWindowInputRow},
    mod_conv_helper_bits,
};
use crate::{
    error::Error,
    ff::{GaloisField, Gf2, PrimeField, Serializable},
    protocol::{
        context::{Context, SemiHonestContext},
        ipa::IPAModulusConvertedInputRow,
        Substep,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare,
};
use std::iter::{once, zip};

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<F, BK>(
    ctx: SemiHonestContext<'_>,
    sorted_match_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    attribution_window_seconds: u32,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BK>>, Error>
where
    F: PrimeField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
{
    let helper_bits_gf2 = compute_helper_bits_gf2(ctx.clone(), &sorted_match_keys).await?;
    let semi_honest_fp_helper_bits = mod_conv_helper_bits(ctx.clone(), &helper_bits_gf2).await?;
    let helper_bits = once(AdditiveShare::ZERO)
        .chain(semi_honest_fp_helper_bits)
        .collect::<Vec<_>>();

    let is_trigger_bits = sorted_rows
        .iter()
        .map(|x| x.is_trigger_bit.clone())
        .collect::<Vec<_>>();
    let stop_bits = compute_stop_bits(ctx.clone(), &is_trigger_bits, &helper_bits)
        .await?
        .collect::<Vec<_>>();

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .map(|(row, hb)| {
            MCApplyAttributionWindowInputRow::new(
                row.timestamp,
                row.is_trigger_bit,
                hb,
                row.breakdown_key,
                row.trigger_value,
            )
        })
        .collect::<Vec<_>>();

    let windowed_reports = apply_attribution_window(
        ctx.narrow(&Step::ApplyAttributionWindow),
        &attribution_input_rows,
        &stop_bits,
        attribution_window_seconds,
    )
    .await?;

    let accumulated_credits = accumulate_credit(
        ctx.narrow(&Step::AccumulateCredit),
        &windowed_reports,
        &stop_bits,
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
    ApplyAttributionWindow,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ApplyAttributionWindow => "apply_attribution_window",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
        }
    }
}
