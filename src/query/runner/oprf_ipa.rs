use std::marker::PhantomData;

use futures::{
    stream::{iter, repeat},
    Stream, StreamExt, TryStreamExt,
};

use crate::{
    error::Error,
    ff::{Gf2, Serializable},
    helpers::{
        query::{IpaQueryConfig, QuerySize},
        BodyStream, LengthDelimitedStream, RecordsStream,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        basics::{Reshare, ShareKnownValue},
        context::{UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext},
        ipa::{ipa, ArithmeticallySharedIPAInputs, IPAInputRow},
        modulus_conversion::BitConversionTriple,
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, BreakdownKey, MatchKey, RecordId,
    },
    report::{EventType, InvalidReportError},
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing, LinearRefOps,
    },
    sync::Arc,
};

pub struct OprfIpaQuery<F, C, S> {
    config: IpaQueryConfig,
    key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C, S)>,
}

impl<F, C, S> OprfIpaQuery<F, C, S> {
    pub fn new(config: IpaQueryConfig, key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            config,
            key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<F, C, S, SB> OprfIpaQuery<F, C, S>
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
    for<'r> &'r SB: LinearRefOps<'r, SB, Gf2>,
    Replicated<F>: Serializable + ShareKnownValue<C, F>,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
    ShuffledPermutationWrapper<S, C::UpgradedContext<F>>: DowngradeMalicious<Target = Vec<u32>>,
    for<'u> UpgradeContext<'u, C::UpgradedContext<F>, F, RecordId>: UpgradeToMalicious<'u, BitConversionTriple<Replicated<F>>, BitConversionTriple<S>>
        + UpgradeToMalicious<
            'u,
            ArithmeticallySharedIPAInputs<F, Replicated<F>>,
            ArithmeticallySharedIPAInputs<F, S>,
        >,
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
            key_registry,
            phantom_data: _,
        } = self;
        tracing::info!("New query: {config:?}");
        let sz = usize::from(query_size);

        let input = if config.plaintext_match_keys {
            let mut v = assert_stream_send(RecordsStream::<
                IPAInputRowOprfVersion<F, MatchKey, BreakdownKey>,
                _,
            >::new(input_stream))
            .try_concat()
            .await?;
            v.truncate(sz); 
            v
        } else {
            panic!();
        };

        attribution_and_capping_and_aggregation(ctx, input.as_slice(), config).await
    }
}

/// Helps to convince the compiler that things are `Send`. Like `seq_join::assert_send`, but for
/// streams.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
pub fn assert_stream_send<'a, T>(
    st: impl Stream<Item = T> + Send + 'a,
) -> impl Stream<Item = T> + Send + 'a {
    st
}