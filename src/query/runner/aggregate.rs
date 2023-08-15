use std::marker::PhantomData;

use futures::Stream;

use crate::{
    error::Error,
    ff::{Gf2, PrimeField, Serializable},
    helpers::{query::QuerySize, BodyStream},
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        basics::{Reshare, ShareKnownValue},
        context::{UpgradableContext, UpgradeContext, UpgradeToMalicious, UpgradedContext},
        ipa::{ArithmeticallySharedIPAInputs, IPAInputRow},
        modulus_conversion::BitConversionTriple,
        sort::generate_permutation::ShuffledPermutationWrapper,
        BasicProtocols, BreakdownKey, MatchKey, RecordId,
    },
    secret_sharing::{
        replicated::{malicious::DowngradeMalicious, semi_honest::AdditiveShare as Replicated},
        Linear as LinearSecretSharing,
    },
    sync::Arc,
};

pub struct AggregateQuery<F, C, S> {
    _key_registry: Arc<KeyRegistry<KeyPair>>,
    phantom_data: PhantomData<(F, C, S)>,
}

impl<F, C, S> AggregateQuery<F, C, S> {
    pub fn new(key_registry: Arc<KeyRegistry<KeyPair>>) -> Self {
        Self {
            _key_registry: key_registry,
            phantom_data: PhantomData,
        }
    }
}

impl<F, C, S, SB> AggregateQuery<F, C, S>
where
    C: UpgradableContext + Send,
    C::UpgradedContext<F>: UpgradedContext<F, Share = S>,
    S: LinearSecretSharing<F>
        + BasicProtocols<C::UpgradedContext<F>, F>
        + Reshare<C::UpgradedContext<F>, RecordId>
        + Serializable
        + DowngradeMalicious<Target = Replicated<F>>
        + 'static,
    C::UpgradedContext<Gf2>: UpgradedContext<Gf2, Share = SB>,
    SB: LinearSecretSharing<Gf2>
        + BasicProtocols<C::UpgradedContext<Gf2>, Gf2>
        + DowngradeMalicious<Target = Replicated<Gf2>>
        + 'static,
    F: PrimeField,
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
    #[tracing::instrument("aggregate_query", skip_all, fields(sz=%query_size))]
    pub async fn execute<'a>(
        self,
        _ctx: C,
        query_size: QuerySize,
        _input_stream: BodyStream,
    ) -> Result<Vec<Replicated<F>>, Error> {
        todo!()
    }
}

/// Helps to convince the compiler that things are `Send`. Like `seq_join::assert_send`, but for
/// streams.
///
/// <https://github.com/rust-lang/rust/issues/102211#issuecomment-1367900125>
pub fn _assert_stream_send<'a, T>(
    st: impl Stream<Item = T> + Send + 'a,
) -> impl Stream<Item = T> + Send + 'a {
    st
}
