use crate::{
    ff::{Field, FieldType, Fp32BitPrime, GaloisField, Serializable},
    helpers::{
        negotiate_prss,
        query::{QueryConfig, QueryType},
        BodyStream, Gateway,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        attribution::input::MCAggregateCreditOutputRow,
        context::{MaliciousContext, SemiHonestContext},
        prss::Endpoint as PrssEndpoint,
        step::{Gate, StepNarrow},
    },
    query::runner::IpaQuery,
    secret_sharing::{replicated::semi_honest::AdditiveShare, Linear as LinearSecretSharing},
    task::JoinHandle,
};

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
use crate::query::runner::execute_test_multiply;
use crate::query::runner::QueryResult;
use futures::FutureExt;
use generic_array::GenericArray;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use std::{
    fmt::Debug,
    future::{ready, Future},
    pin::Pin,
    sync::Arc,
};
use typenum::Unsigned;

pub trait Result: Send + Debug {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<F: Field> Result for Vec<AdditiveShare<F>>
where
    AdditiveShare<F>: Serializable,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * <AdditiveShare<F> as Serializable>::Size::USIZE];
        for (i, share) in self.into_iter().enumerate() {
            share.serialize(GenericArray::from_mut_slice(
                &mut r[i * <AdditiveShare<F> as Serializable>::Size::USIZE
                    ..(i + 1) * <AdditiveShare<F> as Serializable>::Size::USIZE],
            ));
        }

        r
    }
}

impl<F: Field, T: LinearSecretSharing<F>, BK: GaloisField> Result
    for Vec<MCAggregateCreditOutputRow<F, T, BK>>
where
    T: Serializable,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * MCAggregateCreditOutputRow::<F, T, BK>::SIZE];
        for (i, row) in self.into_iter().enumerate() {
            row.serialize(
                &mut r[MCAggregateCreditOutputRow::<F, T, BK>::SIZE * i
                    ..MCAggregateCreditOutputRow::<F, T, BK>::SIZE * (i + 1)],
            );
        }

        r
    }
}

pub fn execute(
    config: QueryConfig,
    key_registry: Arc<KeyRegistry<KeyPair>>,
    gateway: Gateway,
    input: BodyStream,
) -> JoinHandle<QueryResult> {
    match (config.query_type, config.field_type) {
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::TestMultiply, FieldType::Fp31) => {
            do_query(config, gateway, input, |prss, gateway, input| {
                Box::pin(execute_test_multiply::<crate::ff::Fp31>(
                    prss, gateway, input,
                ))
            })
        }
        #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
        (QueryType::TestMultiply, FieldType::Fp32BitPrime) => {
            do_query(config, gateway, input, |prss, gateway, input| {
                Box::pin(execute_test_multiply::<Fp32BitPrime>(prss, gateway, input))
            })
        }
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::SemiHonestIpa(ipa_config), FieldType::Fp31) => {
            do_query(config, gateway, input, move |prss, gateway, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<crate::ff::Fp31, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            })
        }
        (QueryType::SemiHonestIpa(ipa_config), FieldType::Fp32BitPrime) => {
            do_query(config, gateway, input, move |prss, gateway, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<Fp32BitPrime, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            })
        }
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::MaliciousIpa(ipa_config), FieldType::Fp31) => {
            do_query(config, gateway, input, move |prss, gateway, input| {
                let ctx = MaliciousContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<crate::ff::Fp31, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            })
        }
        (QueryType::MaliciousIpa(ipa_config), FieldType::Fp32BitPrime) => {
            do_query(config, gateway, input, move |prss, gateway, input| {
                let ctx = MaliciousContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<Fp32BitPrime, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            })
        }
    }
}

pub fn do_query<F>(
    config: QueryConfig,
    gateway: Gateway,
    input_stream: BodyStream,
    query_impl: F,
) -> JoinHandle<QueryResult>
where
    F: for<'a> FnOnce(
            &'a PrssEndpoint,
            &'a Gateway,
            BodyStream,
        ) -> Pin<Box<dyn Future<Output = QueryResult> + Send + 'a>>
        + Send
        + 'static,
{
    tokio::spawn(async move {
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS first
        let step = Gate::default().narrow(&config.query_type);
        let prss = negotiate_prss(&gateway, &step, &mut rng).await.unwrap();

        query_impl(&prss, &gateway, input_stream).await
    })
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        query::ProtocolResult,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    };

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3)
            .map(Fp31::truncate_from)
            .collect::<Vec<_>>()
            .share();
        let expected = input.clone();
        let bytes = Box::new(input).into_bytes();
        assert_eq!(
            expected,
            AdditiveShare::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
        );
    }
}
