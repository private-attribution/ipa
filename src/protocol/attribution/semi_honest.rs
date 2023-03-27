use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::aggregate_credit,
    compute_helper_bits_gf2,
    credit_capping::credit_capping,
    input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
    mod_conv_gf2_vec, mod_conv_helper_bits,
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
use std::iter::zip;

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<F, BK>(
    ctx: SemiHonestContext<'_>,
    sorted_match_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_breakdown_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    _attribution_window_seconds: u32, // TODO(taikiy): compute the output with the attribution window
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, AdditiveShare<F>, BK>>, Error>
where
    F: PrimeField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
{
    let helper_bits_gf2 = compute_helper_bits_gf2(ctx.clone(), &sorted_match_keys).await?;
    let semi_honest_fp_helper_bits = mod_conv_helper_bits(ctx.clone(), &helper_bits_gf2).await?;
    let helper_bits = Some(AdditiveShare::ZERO)
        .into_iter()
        .chain(semi_honest_fp_helper_bits);

    let attribution_input_rows = zip(sorted_rows, helper_bits)
        .zip(sorted_breakdown_keys)
        .map(|((row, hb), breakdown_key)| {
            MCAccumulateCreditInputRow::new(
                row.is_trigger_bit,
                hb,
                breakdown_key,
                row.trigger_value,
            )
        })
        .collect::<Vec<_>>();

    println!("Starting accumulate credit stage");
    let accumulated_credits = accumulate_credit(
        ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
        per_user_credit_cap,
    )
    .await?;

    println!("Starting user capping stage");
    let user_capped_credits = credit_capping(
        ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;

    println!("Starting aggregate stage");
    aggregate_credit::<F, BK>(
        ctx.narrow(&Step::AggregateCredit),
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
    ModConvHelperBits,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
            Self::ModConvHelperBits => "mod_conv_helper_bits",
        }
    }
}
