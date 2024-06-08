use std::{
    fmt::Debug,
    future::{ready, Future},
    pin::Pin,
};

use ::tokio::sync::oneshot;
use futures::FutureExt;
use generic_array::GenericArray;
use ipa_step::StepNarrow;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use typenum::Unsigned;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
use crate::{ff::Fp32BitPrime, query::runner::execute_test_multiply};
use crate::{
    ff::{boolean_array::BA16, FieldType, Serializable},
    helpers::{
        negotiate_prss,
        query::{QueryConfig, QueryType},
        BodyStream, Gateway,
    },
    hpke::{KeyPair, KeyRegistry},
    protocol::{context::SemiHonestContext, prss::Endpoint as PrssEndpoint, Gate},
    query::{
        runner::{OprfIpaQuery, QueryResult},
        state::RunningQuery,
    },
    sync::Arc,
};

pub trait Result: Send + Debug {
    fn to_bytes(&self) -> Vec<u8>;
}

impl<T> Result for Vec<T>
where
    T: Serializable,
    Vec<T>: Debug + Send,
{
    fn to_bytes(&self) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * T::Size::USIZE];
        for (i, row) in self.iter().enumerate() {
            row.serialize(GenericArray::from_mut_slice(
                &mut r[(i * T::Size::USIZE)..((i + 1) * T::Size::USIZE)],
            ));
        }

        r
    }
}

/// Needless pass by value because IPA v3 does not make use of key registry yet.
#[allow(clippy::too_many_lines, clippy::needless_pass_by_value)]
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
        // TODO(953): This is really using BA32, not Fp32bitPrime. The `FieldType` mechanism needs
        // to be reworked.
        (QueryType::OprfIpa(ipa_config), FieldType::Fp32BitPrime) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    OprfIpaQuery::<BA16>::new(ipa_config, key_registry)
                        .execute(ctx, config.size, input)
                        .then(|res| ready(res.map(|out| Box::new(out) as Box<dyn Result>))),
                )
            },
        ),
        // TODO(953): This is not doing anything differently than the Fp32BitPrime case.
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::OprfIpa(ipa_config), FieldType::Fp31) => do_query(
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                let ctx = SemiHonestContext::new(prss, gateway);
                Box::pin(
                    OprfIpaQuery::<BA16>::new(ipa_config, key_registry)
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
        // Negotiate PRSS using the initial gate for the protocol (no narrowing).
        let prss = negotiate_prss(&gateway, &prss_gate(), &mut rng)
            .await
            .unwrap();

        // Tokio executor is a work-stealing scheduler that optimizes for low latency and
        // resource utilization. It optimizes for low scheduling overhead and uses the same worker
        // threads for polling tasks and to service IO and timer operations, if they are enabled.
        // This leads to very low overhead, but also to an unfortunate possibility of tasks that are
        // long-running to block the entire runtime, even if it is multithreaded.
        // Here is an example in IPA code that led to this discovery:
        // - IPA query kicks in and first step it performs a very large reallocation, keeping the
        // task running for minutes before yielding.
        // - At the time when query started, there was only one active thread in the runtime and
        // it began polling this task
        // - because other threads are parked, there is nothing that can indicate to the executor
        // that there are more tasks that are ready. Tokio Runtime is not polling any task.
        // - Client asks for IPA query status and times out, because IPA application is not
        // responding.
        //
        // Ultimately tokio team decided that it is not a bug in the implementation and made it
        // clear that application needs to take care of it. There are a few ways to deal with it,
        // one of them is to signal the executor that this task is about to block the worker thread
        // for long time, so it has a chance to move the IO driver and pending tasks to other
        // threads. This is what this code does.
        //
        // The issue in tokio repo that describes this behavior
        // https://github.com/tokio-rs/tokio/issues/4730
        let v = if !cfg!(feature = "shuttle")
            && ::tokio::runtime::Handle::current().runtime_flavor()
                == ::tokio::runtime::RuntimeFlavor::MultiThread
        {
            ::tokio::task::block_in_place(|| {
                ::tokio::runtime::Handle::current()
                    .block_on(async { query_impl(&prss, &gateway, &config, input_stream).await })
            })
        } else {
            query_impl(&prss, &gateway, &config, input_stream).await
        };

        tx.send(v).unwrap();
    });

    RunningQuery {
        result: rx,
        join_handle,
    }
}

#[cfg(descriptive_gate)]
fn prss_gate() -> Gate {
    ipa_step::descriptive::Descriptive::default().narrow("prss")
}

#[cfg(compact_gate)]
fn prss_gate() -> Gate {
    use crate::protocol::step::{ProtocolGate, ProtocolStep};

    ProtocolGate::default().narrow(&ProtocolStep::Prss)
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::{Fp31, U128Conversions},
        query::ProtocolResult,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    };

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3).map(Fp31::truncate_from).share();
        let expected = input.clone();
        let bytes = &input.to_bytes();
        assert_eq!(
            expected,
            AdditiveShare::<Fp31>::from_byte_slice(bytes)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        );
    }
}
