use std::{borrow::Borrow, fmt::Debug, future::Future, pin::Pin};

use ::tokio::{
    runtime::{Handle, RuntimeFlavor},
    sync::oneshot,
    task::block_in_place,
};
use generic_array::GenericArray;
use ipa_step::StepNarrow;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use typenum::Unsigned;

#[cfg(any(
    test,
    feature = "cli",
    feature = "test-fixture",
    feature = "weak-field"
))]
use crate::ff::FieldType;
use crate::{
    executor::IpaRuntime,
    ff::Serializable,
    helpers::{
        negotiate_prss,
        query::{QueryConfig, QueryType},
        BodyStream, Gateway,
    },
    hpke::PrivateKeyRegistry,
    protocol::{prss::Endpoint as PrssEndpoint, Gate},
    query::{
        runner::{execute_hybrid_protocol, QueryResult},
        state::RunningQuery,
    },
    sync::Arc,
};
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
use crate::{
    ff::Fp32BitPrime, query::runner::execute_sharded_shuffle, query::runner::execute_test_multiply,
    query::runner::test_add_in_prime_field,
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
pub fn execute<R: PrivateKeyRegistry>(
    runtime: &IpaRuntime,
    config: QueryConfig,
    key_registry: Arc<R>,
    gateway: Gateway,
    input: BodyStream,
) -> RunningQuery {
    match (config.query_type, config.field_type) {
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::TestMultiply, FieldType::Fp31) => do_query(
            runtime,
            config,
            gateway,
            input,
            |prss, gateway, _config, input| {
                Box::pin(execute_test_multiply::<crate::ff::Fp31>(
                    prss, gateway, input,
                ))
            },
        ),
        #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
        (QueryType::TestMultiply, FieldType::Fp32BitPrime) => do_query(
            runtime,
            config,
            gateway,
            input,
            |prss, gateway, _config, input| {
                Box::pin(execute_test_multiply::<Fp32BitPrime>(prss, gateway, input))
            },
        ),
        #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
        (QueryType::TestShardedShuffle, _) => do_query(
            runtime,
            config,
            gateway,
            input,
            |prss, gateway, _config, input| Box::pin(execute_sharded_shuffle(prss, gateway, input)),
        ),
        #[cfg(any(test, feature = "weak-field"))]
        (QueryType::TestAddInPrimeField, FieldType::Fp31) => do_query(
            runtime,
            config,
            gateway,
            input,
            |prss, gateway, _config, input| {
                Box::pin(test_add_in_prime_field::<crate::ff::Fp31>(
                    prss, gateway, input,
                ))
            },
        ),
        #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
        (QueryType::TestAddInPrimeField, FieldType::Fp32BitPrime) => do_query(
            runtime,
            config,
            gateway,
            input,
            |prss, gateway, _config, input| {
                Box::pin(test_add_in_prime_field::<Fp32BitPrime>(
                    prss, gateway, input,
                ))
            },
        ),
        (QueryType::MaliciousHybrid(ipa_config), _) => do_query(
            runtime,
            config,
            gateway,
            input,
            move |prss, gateway, config, input| {
                Box::pin(execute_hybrid_protocol(
                    prss,
                    gateway,
                    input,
                    ipa_config,
                    config,
                    key_registry,
                ))
            },
        ),
    }
}

pub fn do_query<B, F>(
    executor_handle: &IpaRuntime,
    config: QueryConfig,
    gateway: B,
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
    B: Borrow<Gateway> + Send + 'static,
{
    let (tx, rx) = oneshot::channel();

    let join_handle = executor_handle.spawn(async move {
        let gateway = gateway.borrow();
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS using the initial gate for the protocol (no narrowing).
        let prss = negotiate_prss(gateway, &prss_gate(), &mut rng)
            .await
            .unwrap();

        // see private-attribution/ipa#1120
        let v = if !cfg!(feature = "shuttle")
            && Handle::current().runtime_flavor() == RuntimeFlavor::MultiThread
        {
            block_in_place(|| {
                // block_on runs on the current thread, so if it is also responsible for IO
                // it's been handed off already by block_in_place.
                Handle::current()
                    .block_on(async { query_impl(&prss, gateway, &config, input_stream).await })
            })
        } else {
            query_impl(&prss, gateway, &config, input_stream).await
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
    use std::{array, future::Future, iter::zip, sync::Arc, time::Duration};

    use futures::future::join_all;
    use tokio::sync::Barrier;

    use crate::{
        executor::IpaRuntime,
        ff::{FieldType, Fp31, U128Conversions},
        helpers::{
            query::{QueryConfig, QueryType},
            BodyStream, Gateway, Role,
        },
        query::{executor::do_query, state::RunningQuery, ProtocolResult},
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_fixture::TestWorld,
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

    #[tokio::test]
    async fn does_not_block_tokio_runtime() {
        let world = Box::leak(Box::<TestWorld>::default());
        let world_ptr = world as *mut _;

        let gateways = [
            world.gateway(Role::H1),
            world.gateway(Role::H2),
            world.gateway(Role::H3),
        ];

        let runtimes: [_; 3] = array::from_fn(|_| {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(3)
                .enable_all()
                .build()
                .unwrap()
        });

        let handles: Vec<_> = zip(runtimes.iter(), gateways)
            .map(|(rt, gateway)| {
                let _guard = rt.enter();

                // we simulate the deadlock only on H1, it is enough to reproduce the issue
                if gateway.role() == Role::H1 {
                    let barrier = Arc::new(Barrier::new(3));

                    // this task simulates busy loop. it will block its worker thread and,
                    // if scheduled properly, must not affect the other tasks running on this
                    // runtime
                    let h1_query = query_task(gateway, {
                        let barrier = Arc::clone(&barrier);
                        || async move {
                            barrier.wait().await;
                            // using IO or timer is crucial to reproduce the issue with
                            // tokio runtime (see tokio/4730)
                            tokio::time::sleep(Duration::from_secs(1)).await;
                            #[allow(clippy::empty_loop)]
                            loop {
                                // uncomment the following line to prevent the deadlock with
                                // tokio::spawn
                                // tokio::task::yield_now().await;
                            }
                        }
                    });

                    // task that must run to completion even when the previous one
                    // is blocked
                    let h2 = rt.spawn({
                        let b_2 = Arc::clone(&barrier);
                        async move {
                            b_2.wait().await;
                            // this must sleep longer than busy task to miss the chance of being
                            // woken up
                            tokio::time::sleep(Duration::from_secs(5)).await;

                            42
                        }
                    });

                    // main task unblocks both tasks and expects one of them to make progress.
                    tokio::spawn({
                        let barrier = Arc::clone(&barrier);
                        async move {
                            barrier.wait().await;

                            // h1 is locked forever, but h2 should be able to run to completion
                            assert_eq!(42, h2.await.unwrap());
                            h1_query.join_handle.abort();
                        }
                    })
                } else {
                    // other helpers don't need to do anything
                    tokio::spawn(async move {
                        query_task(gateway, || futures::future::ready(()))
                            .await
                            .unwrap();
                    })
                }
            })
            .collect();

        join_all(handles).await;

        for runtime in runtimes {
            runtime.shutdown_background();
        }

        let _ = unsafe { Box::from_raw(world_ptr) };
    }

    fn query_task<F, Fut>(gateway: &'static Gateway, f: F) -> RunningQuery
    where
        F: Send + 'static + FnOnce() -> Fut,
        Fut: Future<Output = ()> + Send,
    {
        do_query(
            &IpaRuntime::current(),
            QueryConfig {
                size: 1.try_into().unwrap(),
                field_type: FieldType::Fp31,
                query_type: QueryType::TestMultiply,
            },
            gateway,
            BodyStream::empty(),
            move |_, _, _, _| {
                Box::pin(async move {
                    f().await;
                    Ok(Box::<Vec<Fp31>>::default() as Box<dyn ProtocolResult>)
                })
            },
        )
    }
}
