use std::marker::PhantomData;

use futures_util::TryStreamExt;

use super::ipa::assert_stream_send;
use crate::{
    error::Error,
    ff::{Gf2, Gf8Bit, PrimeField, Serializable},
    helpers::{
        query::{QuerySize, SparseAggregateQueryConfig},
        BodyStream, RecordsStream,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        aggregation::{sparse_aggregate, SparseAggregateInputRow},
        basics::{Reshare, ShareKnownValue},
        context::{UpgradableContext, UpgradedContext},
        BasicProtocols, BreakdownKey, RecordId,
    },
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing, LinearRefOps,
    },
    sync::Arc,
};

pub struct SparseAggregateQuery<F, C, S> {
    config: SparseAggregateQueryConfig,
    _key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C, S)>,
}

impl<F, C, S> SparseAggregateQuery<F, C, S> {
    pub fn new(
        config: SparseAggregateQueryConfig,
        key_registry: Arc<KeyRegistry<KeyPair>>,
    ) -> Self {
        Self {
            config,
            _key_registry: key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<F, C, S, SB> SparseAggregateQuery<F, C, S>
where
    C: UpgradableContext + Send,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    for<'r> &'r S: LinearRefOps<'r, S, F>,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    SparseAggregateInputRow<Gf8Bit, BreakdownKey>: Serializable,
{
    #[tracing::instrument("sparse_aggregate_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let Self {
            config,
            _key_registry,
            phantom_data: _,
        } = self;
        let sz = usize::from(query_size);

        //TODO(taikiy):
        // 1. decrypt the input
        // 2. deserialize the input into `AggregateInputRow` with `contribution_bits` size field

        let input = {
            //TODO: Replace `Gf8Bit` with an appropriate type specified by the config `contribution_bits`
            let mut v = assert_stream_send(RecordsStream::<
                SparseAggregateInputRow<Gf8Bit, BreakdownKey>,
                _,
            >::new(input_stream))
            .try_concat()
            .await?;
            v.truncate(sz);
            v
        };

        sparse_aggregate(
            ctx,
            input.as_slice(),
            usize::try_from(config.num_contributions).unwrap(),
        )
        .await
    }
}
