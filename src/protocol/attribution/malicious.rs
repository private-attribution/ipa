use super::{
    accumulate_credit::accumulate_credit,
    aggregate_credit::malicious_aggregate_credit,
    credit_capping::credit_capping,
    input::{MCAccumulateCreditInputRow, MCAggregateCreditOutputRow},
};
use crate::{
    error::Error,
    ff::{GaloisField, PrimeField, Serializable},
    protocol::{
        boolean::bitwise_equal::bitwise_equal,
        context::{Context, SemiHonestContext},
        ipa::IPAModulusConvertedInputRow,
        malicious::MaliciousValidator,
        RecordId, Substep,
    },
    secret_sharing::replicated::{
        malicious::AdditiveShare, semi_honest::AdditiveShare as SemiHonestAdditiveShare,
    },
};
use futures::future::try_join_all;
use std::iter::{repeat, zip};

/// Performs a set of attribution protocols on the sorted IPA input.
///
/// # Errors
/// propagates errors from multiplications
pub async fn secure_attribution<'a, F, BK>(
    sh_ctx: SemiHonestContext<'a>,
    malicious_validator: MaliciousValidator<'a, F>,
    sorted_rows: Vec<IPAModulusConvertedInputRow<F, AdditiveShare<F>>>,
    per_user_credit_cap: u32,
    max_breakdown_key: u32,
    num_multi_bits: u32,
) -> Result<Vec<MCAggregateCreditOutputRow<F, SemiHonestAdditiveShare<F>, BK>>, Error>
where
    F: PrimeField,
    BK: GaloisField,
    AdditiveShare<F>: Serializable,
    SemiHonestAdditiveShare<F>: Serializable,
{
    let m_ctx = malicious_validator.context();

    let futures = zip(
        repeat(
            m_ctx
                .narrow(&Step::ComputeHelperBits)
                .set_total_records(sorted_rows.len() - 1),
        ),
        sorted_rows.iter(),
    )
    .zip(sorted_rows.iter().skip(1))
    .enumerate()
    .map(|(i, ((m_ctx, row), next_row))| {
        let record_id = RecordId::from(i);
        async move { bitwise_equal(m_ctx, record_id, &row.mk_shares, &next_row.mk_shares).await }
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

    let (malicious_validator, output) = malicious_aggregate_credit::<F, BK>(
        malicious_validator,
        sh_ctx,
        user_capped_credits.into_iter(),
        max_breakdown_key,
        num_multi_bits,
    )
    .await?;

    //Validate before returning the result to the report collector
    malicious_validator.validate(output).await
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    ComputeHelperBits,
    AccumulateCredit,
    PerformUserCapping,
    AggregateCredit,
}

impl Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ComputeHelperBits => "compute_helper_bits",
            Self::AccumulateCredit => "accumulate_credit",
            Self::PerformUserCapping => "user_capping",
            Self::AggregateCredit => "aggregate_credit",
        }
    }
}
