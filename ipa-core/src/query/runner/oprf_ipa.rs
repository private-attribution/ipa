use std::marker::PhantomData;

use futures::TryStreamExt;

use crate::{
    error::Error,
    ff::{
        boolean::Boolean,
        boolean_array::{BA20, BA3, BA4, BA5, BA6, BA7, BA8},
        PrimeField, Serializable,
    },
    helpers::{
        query::{IpaQueryConfig, QuerySize},
        BodyStream, RecordsStream,
    },
    protocol::{
        basics::ShareKnownValue,
        context::{UpgradableContext, UpgradedContext},
        ipa_prf::oprf_ipa,
    },
    report::OprfReport,
    secret_sharing::replicated::{
        malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
    },
};

pub struct OprfIpaQuery<C, F> {
    config: IpaQueryConfig,
    phantom_data: PhantomData<(C, F)>,
}

impl<C, F> OprfIpaQuery<C, F> {
    pub fn new(config: IpaQueryConfig) -> Self {
        Self {
            config,
            phantom_data: PhantomData,
        }
    }
}

#[allow(clippy::too_many_lines)]
impl<C, F> OprfIpaQuery<C, F>
where
    C: UpgradableContext,
    C::UpgradedContext<F>: UpgradedContext<F, Share = Replicated<F>>,
    C::UpgradedContext<Boolean>: UpgradedContext<Boolean, Share = Replicated<Boolean>>,
    F: PrimeField + ExtendableField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    Replicated<Boolean>: Serializable + ShareKnownValue<C, Boolean>,
{
    #[tracing::instrument("oprf_ipa_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let Self {
            config,
            phantom_data: _,
        } = self;
        tracing::info!("New query: {config:?}");
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            let mut v = RecordsStream::<OprfReport<BA8, BA3, BA20>, _>::new(input_stream)
                .try_concat()
                .await?;
            v.truncate(sz);
            v
        } else {
            LengthDelimitedStream::<EncryptedReport<F, MatchKey, BreakdownKey, _>, _>::new(
                input_stream,
            )
                .map_err(Into::<Error>::into)
                .map_ok(|enc_reports| {
                    iter(enc_reports.into_iter().map(|enc_report| {
                        enc_report
                            .decrypt(key_registry.as_ref())
                            .map_err(Into::<Error>::into)
                    }))
                })
                .try_flatten()
                .take(sz)
                .zip(repeat(ctx.clone()))
                .map(|(res, ctx)| {
                    res.and_then(|report| {
                        let timestamp = Replicated::<F>::share_known_value(
                            &ctx,
                            F::try_from(report.timestamp.into())
                                .map_err(|_| InvalidReportError::Timestamp(report.timestamp))?,
                        );
                        let breakdown_key =
                            Replicated::<BreakdownKey>::share_known_value(&ctx, report.breakdown_key);
                        let is_trigger_bit = Replicated::<F>::share_known_value(
                            &ctx,
                            match report.event_type {
                                EventType::Source => F::ZERO,
                                EventType::Trigger => F::ONE,
                            },
                        );

                        Ok(IPAInputRow {
                            timestamp,
                            mk_shares: report.mk_shares,
                            is_trigger_bit,
                            breakdown_key,
                            trigger_value: report.trigger_value,
                        })
                    })
                })
                .try_collect::<Vec<_>>()
                .await?
        };

        let aws = config.attribution_window_seconds;
        match config.per_user_credit_cap {
            8 => oprf_ipa::<C, BA8, BA3, BA20, BA3, F>(ctx, input, aws).await,
            16 => oprf_ipa::<C, BA8, BA3, BA20, BA4, F>(ctx, input, aws).await,
            32 => oprf_ipa::<C, BA8, BA3, BA20, BA5, F>(ctx, input, aws).await,
            64 => oprf_ipa::<C, BA8, BA3, BA20, BA6, F>(ctx, input, aws).await,
            128 => oprf_ipa::<C, BA8, BA3, BA20, BA7, F>(ctx, input, aws).await,
            _ => panic!(
                "Invalid value specified for per-user cap: {:?}. Must be one of 8, 16, 32, 64, or 128.",
                config.per_user_credit_cap
            ),
        }
    }
}
