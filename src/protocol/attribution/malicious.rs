use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::malicious_aggregate_credit,
    apply_attribution_window::apply_attribution_window,
    compute_helper_bits_gf2, compute_stop_bits,
    credit_capping::credit_capping,
    input::{MCAggregateCreditOutputRow, MCApplyAttributionWindowInputRow},
    mod_conv_helper_bits,
};
use crate::{
    error::Error,
    ff::{GaloisField, Gf2, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    protocol::{
        context::{Context, SemiHonestContext},
        ipa::IPAModulusConvertedInputRow,
        malicious::MaliciousValidator,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare, ExtendableField},
        semi_honest::AdditiveShare as SemiHonestAdditiveShare,
    },
};
use std::iter::{once, zip};

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<'a, F, BK>(
    sh_ctx: SemiHonestContext<'a>,
    malicious_validator: MaliciousValidator<'a, F>,
    binary_malicious_validator: MaliciousValidator<'a, Gf2>,
    sorted_match_keys: Vec<Vec<AdditiveShare<Gf2>>>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    config: IpaQueryConfig,
) -> Result<Vec<MCAggregateCreditOutputRow<F, SemiHonestAdditiveShare<F>, BK>>, Error>
where
    F: PrimeField + ExtendableField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
    SemiHonestAdditiveShare<F>: Serializable,
{
    let m_ctx = malicious_validator.context();
    let m_binary_ctx = binary_malicious_validator.context();

    let helper_bits_gf2 = compute_helper_bits_gf2(m_binary_ctx, &sorted_match_keys).await?;
    let validated_helper_bits_gf2 = binary_malicious_validator.validate(helper_bits_gf2).await?;
    let semi_honest_fp_helper_bits =
        mod_conv_helper_bits(sh_ctx.clone(), &validated_helper_bits_gf2).await?;
    let helper_bits = once(AdditiveShare::ZERO)
        .chain(m_ctx.upgrade(semi_honest_fp_helper_bits).await?)
        .collect::<Vec<_>>();

    let is_trigger_bits = sorted_rows
        .iter()
        .map(|x| x.is_trigger_bit.clone())
        .collect::<Vec<_>>();
    let stop_bits = compute_stop_bits(m_ctx.clone(), &is_trigger_bits, &helper_bits)
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
        m_ctx.narrow(&Step::ApplyAttributionWindow),
        &attribution_input_rows,
        &stop_bits,
        config.attribution_window_seconds,
    )
    .await?;

    let accumulated_credits = accumulate_credit(
        m_ctx.narrow(&Step::AccumulateCredit),
        &windowed_reports,
        &stop_bits,
        config.per_user_credit_cap,
        config.attribution_window_seconds,
    )
    .await?;

    let user_capped_credits = credit_capping(
        m_ctx.narrow(&Step::PerformUserCapping),
        &accumulated_credits,
        config.per_user_credit_cap,
    )
    .await?;

    let (malicious_validator, output) = malicious_aggregate_credit::<F, BK>(
        malicious_validator,
        sh_ctx,
        user_capped_credits.into_iter(),
        config.max_breakdown_key,
        config.num_multi_bits,
    )
    .await?;

    //Validate before returning the result to the report collector
    malicious_validator.validate(output).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    ApplyAttributionWindow,
    AccumulateCredit,
    PerformUserCapping,
}

impl crate::protocol::step::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ApplyAttributionWindow => "apply_attribution_window",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
        }
    }
}
