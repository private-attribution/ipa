use std::marker::PhantomData;

use futures_util::TryStreamExt;

use super::ipa::assert_stream_send;
use crate::{
    error::Error,
    ff::{Gf2, PrimeField, Serializable},
    helpers::{query::QuerySize, BodyStream, RecordsStream},
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        aggregation::{aggregate, AggregateInputRow},
        basics::ShareKnownValue,
        context::{UpgradableContext, UpgradedContext},
        BasicProtocols, BreakdownKey, ConversionValue,
    },
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing,
    },
    sync::Arc,
};

pub struct AggregateQuery<F, C> {
    _key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C)>,
}

impl<F, C> AggregateQuery<F, C> {
    pub fn new(key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            _key_registry: key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<F, C, SB> AggregateQuery<F, C>
where
    C: UpgradableContext + Send,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    AggregateInputRow<ConversionValue, BreakdownKey>: Serializable,
{
    #[tracing::instrument("aggregate_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        ctx: C,
        query_size: QuerySize,
        input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        let Self {
            _key_registry,
            phantom_data: _,
        } = self;
        let sz = usize::from(query_size);

        //TODO(taikiy): decrypt the input

        let input = {
            let mut v = assert_stream_send(RecordsStream::<
                AggregateInputRow<ConversionValue, BreakdownKey>,
                _,
            >::new(input_stream))
            .try_concat()
            .await?;
            v.truncate(sz);
            v
        };

        aggregate(ctx, input.as_slice()).await
    }
}
