use std::{marker::PhantomData, sync::Arc};

use futures::{stream::iter, StreamExt, TryStreamExt};

use crate::{
    error::Error,
    ff::boolean_array::{BA20, BA3, BA8},
    helpers::{
        query::{HybridQueryParams, QuerySize},
        BodyStream, LengthDelimitedStream,
    },
    hpke::PrivateKeyRegistry,
    protocol::{context::UpgradableContext, ipa_prf::shuffle::Shuffle, step::ProtocolStep::Hybrid},
    report::EncryptedOprfReport,
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
        let _ctx = ctx.narrow(&Hybrid);
        let sz = usize::from(query_size);

        let _input = if config.plaintext_match_keys {
            unimplemented!()
        } else {
            let _encrypted_oprf_reports = LengthDelimitedStream::<
                EncryptedOprfReport<BA8, BA3, BA20, _>,
                _,
            >::new(input_stream)
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
            .try_collect::<Vec<_>>()
            .await?;
        };

        unimplemented!()
    }
}
