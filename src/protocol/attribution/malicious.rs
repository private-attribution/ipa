use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::malicious_aggregate_credit,
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
        malicious::MaliciousValidator,
        Substep,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare, ExtendableField},
        semi_honest::AdditiveShare as SemiHonestAdditiveShare,
    },
};
use std::iter::zip;

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
#[allow(clippy::too_many_arguments)]
pub async fn secure_attribution<'a, F, BK>(
    sh_ctx: SemiHonestContext<'a>,
    malicious_validator: MaliciousValidator<'a, F>,
    match_key_malicious_validator: MaliciousValidator<'a, Gf2>,
    breakdown_key_validator: MaliciousValidator<'a, Gf2>,
    sorted_breakdown_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_match_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    _attribution_window_seconds: u32, // TODO(taikiy): compute the output with the attribution window
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, SemiHonestAdditiveShare<F>, BK>>, Error>
where
    F: PrimeField + ExtendableField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
    SemiHonestAdditiveShare<F>: Serializable,
{
    let m_ctx = malicious_validator.context();
    let m_binary_ctx = match_key_malicious_validator.context();

    let helper_bits_gf2 = compute_helper_bits_gf2(m_binary_ctx, &sorted_match_keys).await?;
    let validated_helper_bits_gf2 = match_key_malicious_validator
        .validate(helper_bits_gf2)
        .await?;
    let semi_honest_fp_helper_bits =
        mod_conv_helper_bits(sh_ctx.clone(), &validated_helper_bits_gf2).await?;
    let helper_bits = Some(AdditiveShare::ZERO)
        .into_iter()
        .chain(m_ctx.upgrade(semi_honest_fp_helper_bits).await?);

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
    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&Step::AccumulateCredit),
        &attribution_input_rows,
        per_user_credit_cap,
    )
    .await?;
    let user_capped_credits = credit_capping(
        m_ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        per_user_credit_cap,
    )
    .await?;
    let num_records = user_capped_credits.len();
    let (malicious_validator, output) = malicious_aggregate_credit::<F, BK>(
        malicious_validator,
        breakdown_key_validator,
        sh_ctx,
        &user_capped_credits,
        max_breakdown_key,
        num_multi_bits,
    )
    .await?;
    //Validate before returning the result to the report collector
    malicious_validator.validate(output).await
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
