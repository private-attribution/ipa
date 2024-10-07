use std::{marker::PhantomData, sync::Arc};

use crate::{
    error::Error,
    ff::boolean_array::{BA20, BA3, BA8},
    helpers::{
        query::{HybridQueryParams, QuerySize},
        BodyStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{context::UpgradableContext, ipa_prf::shuffle::Shuffle},
    secret_sharing::{replicated::semi_honest::AdditiveShare as ReplicatedShare, SharedValue},
};

pub struct Query<C, HV, R: PrivateKeyRegistry> {
    config: HybridQueryParams,
    key_registry: Arc<R>,
    phantom_data: PhantomData<(C, HV)>,
}

impl<C, HV: SharedValue, R: PrivateKeyRegistry> Query<C, HV, R>
where
    C: UpgradableContext + Shuffle,
{
    pub fn new(query_params: HybridQueryParams, key_registry: Arc<R>) -> Self {
        Self {
            config: query_params,
            key_registry,
            phantom_data: PhantomData,
        }
    }

    #[tracing::instrument("hybrid_query", skip_all, fields(sz=%query_size))]
    pub async fn execute(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<ReplicatedShare<HV>>, Error> {
        let Self {
            config,
            key_registry,
            phantom_data: _,
        } = self;
        tracing::info!("New hybrid query: {config:?}");
        let ctx = ctx.narrow(&IpaPrf);
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            unimplemented!()
        } else {
            LengthDelimitedStream::<EncryptedOprfReport<BA8, BA3, BA20, _>, _>::new(input_stream)
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
                    res.map(|report| {
                        let is_trigger = Replicated::<Boolean>::share_known_value(
                            &ctx,
                            match report.event_type {
                                EventType::Source => Boolean::ZERO,
                                EventType::Trigger => Boolean::ONE,
                            },
                        );

                        OPRFIPAInputRow {
                            timestamp: report.timestamp,
                            match_key: report.match_key,
                            is_trigger,
                            breakdown_key: report.breakdown_key,
                            trigger_value: report.trigger_value,
                        }
                    })
                })
                .try_collect::<Vec<_>>()
                .await?
        };

        unimplemented!()
    }
}
