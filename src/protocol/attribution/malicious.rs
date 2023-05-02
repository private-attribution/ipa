use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::aggregate_credit,
    apply_attribution_window::apply_attribution_window,
    compute_helper_bits_gf2, compute_stop_bits,
    credit_capping::credit_capping,
    input::{
        MCAggregateCreditOutputRow, MCApplyAttributionWindowInputRow,
        MCCappedCreditsWithAggregationBit,
    },
    mod_conv_helper_bits,
};
use crate::{
    error::Error,
    ff::{GaloisField, Gf2, PrimeField, Serializable},
    helpers::query::IpaQueryConfig,
    protocol::{
        boolean::RandomBits,
        context::{Context, UpgradableContext, UpgradedContext},
        ipa::IPAModulusConvertedInputRow,
        malicious::Validator,
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, Substep,
    },
    secret_sharing::{
        replicated::{
            malicious::{DowngradeMalicious, ExtendableField},
            semi_honest::AdditiveShare as SemiHonestAdditiveShare,
        },
        Linear as LinearSecretSharing,
    },
};
use std::iter::{once, zip};

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<C, S, SB, F, BK>(
    sh_ctx: C,
    validator: C::Validator<F>,
    binary_validator: C::Validator<Gf2>,
    sorted_match_keys: Vec<Vec<SB>>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, S>>,
    config: IpaQueryConfig,
) -> Result<Vec<MCAggregateCreditOutputRow<F, SemiHonestAdditiveShare<F>, BK>>, Error>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S> + RandomBits<F, Share = S>,
    S: LinearSecretSharing<F> + BasicProtocols<C::UpgradedContext<F>, F> + Serializable + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB> + Context,
    SB: LinearSecretSharing<Gf2> + BasicProtocols<C::UpgradedContext<Gf2>, Gf2> + 'static,
    Vec<SB>: DowngradeMalicious<Target = Vec<SemiHonestAdditiveShare<Gf2>>>,
    F: PrimeField + ExtendableField,
    BK: GaloisField,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    MCCappedCreditsWithAggregationBit<F, S>: DowngradeMalicious<
        Target = MCCappedCreditsWithAggregationBit<F, SemiHonestAdditiveShare<F>>,
    >,
    MCAggregateCreditOutputRow<F, S, BK>:
        DowngradeMalicious<Target = MCAggregateCreditOutputRow<F, SemiHonestAdditiveShare<F>, BK>>,
{
    let m_ctx = validator.context();
    let m_binary_ctx = binary_validator.context();

    let helper_bits_gf2 = compute_helper_bits_gf2(m_binary_ctx, &sorted_match_keys).await?;
    let validated_helper_bits_gf2 = binary_validator.validate(helper_bits_gf2).await?;
    let semi_honest_fp_helper_bits =
        mod_conv_helper_bits(sh_ctx.clone(), &validated_helper_bits_gf2).await?;
    let helper_bits = once(S::ZERO)
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

    let (validator, output) = aggregate_credit(
        validator,
        sh_ctx,
        user_capped_credits.into_iter(),
        config.max_breakdown_key,
        config.num_multi_bits,
    )
    .await?;

    //Validate before returning the result to the report collector
    validator.validate(output).await
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
