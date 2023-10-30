use std::{
    fmt::Debug,
    future::{ready, Future},
    pin::Pin,
    sync::Arc,
};

use ::tokio::sync::oneshot;
use futures::FutureExt;
use generic_array::GenericArray;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use typenum::Unsigned;

use super::runner::OprfIpaQuery;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
use crate::query::runner::execute_test_multiply;
use crate::{
    ff::{FieldType, Fp32BitPrime, Serializable},
    helpers::{
        negotiate_prss,
        query::{QueryConfig, QueryType},
        BodyStream, Gateway,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{
        context::{MaliciousContext, SemiHonestContext},
        prss::Endpoint as PrssEndpoint,
        step::{Gate, StepNarrow},
    },
    query::{
        runner::{IpaQuery, QueryResult, SparseAggregateQuery},
        state::RunningQuery,
    },
};

pub trait Result: Send + Debug {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<T> Result for Vec<T>
where
    T: Serializable,
    Vec<T>: Debug + Send,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * T::Size::USIZE];
        for (i, row) in self.into_iter().enumerate() {
            row.serialize(GenericArray::from_mut_slice(
                &mut r[(i * T::Size::USIZE)..((i + 1) * T::Size::USIZE)],
            ));
        }

        r
    }
}

#[allow(clippy::too_many_lines)]
pub fn execute(
    config: QueryConfig,
    key_registry: Arc<KeyRegistry<KeyPair>>,
    gateway: Gateway,
    input: BodyStream,
) -> RunningQuery {
    match (config.query_type, config.field_type) {
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::TestMultiply, FieldType::Fp31) => {
            do_query(config, gateway, input, |prss, gateway, _config, input| {
                Box::pin(execute_test_multiply::<crate::ff::Fp31>(
                    prss, gateway, input,
                ))
            })
        }
        #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
        (QueryType::TestMultiply, FieldType::Fp32BitPrime) => {
            do_query(config, gateway, input, |prss, gateway, _config, input| {
                Box::pin(execute_test_multiply::<Fp32BitPrime>(prss, gateway, input))
            })
        }
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::SemiHonestIpa(ipa_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<crate::ff::Fp31, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        (QueryType::SemiHonestIpa(ipa_config), FieldType::Fp32BitPrime) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<Fp32BitPrime, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::MaliciousIpa(ipa_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = MaliciousContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<crate::ff::Fp31, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        (QueryType::MaliciousIpa(ipa_config), FieldType::Fp32BitPrime) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = MaliciousContext::new(prss, gateway);
                Box::pin(
                    IpaQuery::<Fp32BitPrime, _, _>::new(ipa_config, key_registry)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::SemiHonestSparseAggregate(aggregate_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    SparseAggregateQuery::<crate::ff::Fp31, _, _>::new(
                        aggregate_config,
                        key_registry,
                    )
                    .execute(ctx, config.size, input)
                    .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        (QueryType::SemiHonestSparseAggregate(aggregate_config), FieldType::Fp32BitPrime) => {
            do_query(
                config,
                gateway,
                input,
                move |prss, gateway, config, input| {
                    let ctx = SemiHonestContext::new(prss, gateway);
                    Box::pin(
                        SparseAggregateQuery::<Fp32BitPrime, _, _>::new(
                            aggregate_config,
                            key_registry,
                        )
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                    )
                },
            )
        }
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::MaliciousSparseAggregate(aggregate_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = MaliciousContext::new(prss, gateway);
                Box::pin(
                    SparseAggregateQuery::<crate::ff::Fp31, _, _>::new(
                        aggregate_config,
                        key_registry,
                    )
                    .execute(ctx, config.size, input)
                    .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        (QueryType::MaliciousSparseAggregate(aggregate_config), FieldType::Fp32BitPrime) => {
            do_query(
                config,
                gateway,
                input,
                move |prss, gateway, config, input| {
                    let ctx = MaliciousContext::new(prss, gateway);
                    Box::pin(
                        SparseAggregateQuery::<Fp32BitPrime, _, _>::new(
                            aggregate_config,
                            key_registry,
                        )
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                    )
                },
            )
        }
        (QueryType::OprfIpa(ipa_config), FieldType::Fp32BitPrime) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    OprfIpaQuery::<_, Fp32BitPrime>::new(ipa_config)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::OprfIpa(ipa_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    OprfIpaQuery::<_, Fp32BitPrime>::new(ipa_config)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
    }
}

pub fn do_query<F>(
    config: QueryConfig,
    gateway: Gateway,
    input_stream: BodyStream,
    query_impl: F,
) -> RunningQuery
where
    F: for<'a> FnOnce(
            &'a PrssEndpoint,
            &'a Gateway,
            &'a QueryConfig,
            BodyStream,
        ) -> Pin<Box<dyn Future<Output = QueryResult> + Send + 'a>>
        + Send
        + 'static,
{
    let (tx, rx) = oneshot::channel();

    let join_handle = tokio::spawn(async move {
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS first
        let step = Gate::default().narrow(&config.query_type);
        let prss = negotiate_prss(&gateway, &step, &mut rng).await.unwrap();

        tx.send(query_impl(&prss, &gateway, &config, input_stream).await)
            .unwrap();
    });

    RunningQuery {
        result: rx,
        join_handle,
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Field, Fp31},
        query::ProtocolResult,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    };

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3).map(Fp31::truncate_from).share();
        let expected = input.clone();
        let bytes = Box::new(input).into_bytes();
        assert_eq!(
            expected,
            AdditiveShare::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
        );
    }
}
