use std::{
    collections::hash_map::Entry,
    fmt::{Debug, Formatter},
};

use futures::{future::try_join, stream};
use serde::Serialize;

use crate::{
    error::Error as ProtocolError,
    executor::IpaRuntime,
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        Gateway, GatewayConfig, MpcTransportError, MpcTransportImpl, Role, RoleAssignment,
        ShardTransportImpl, Transport,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    protocol::QueryId,
    query::{
        executor,
        state::{QueryState, QueryStatus, RemoveQuery, RunningQueries, StateError},
        CompletionHandle, ProtocolResult,
    },
    sync::Arc,
    utils::NonZeroU32PowerOfTwo,
};

/// `Processor` accepts and tracks requests to initiate new queries on this helper party
/// network. It makes sure queries are coordinated and each party starts processing it when
/// it has all the information required.
///
/// Query processing consists of multiple steps:
/// - A new request to initiate a query arrives from an external party (report collector) to any of the
///     helpers.
/// - Upon receiving that request, helper chooses a unique [`QueryId`] and assigns [`Role`] to every
///     helper. It informs other parties about it and awaits their response.
/// - If all parties accept the proposed query, they negotiate shared randomness and signal that
///     they're ready to receive inputs.
/// - Each party, upon receiving the input as a set of [`AdditiveShare`], immediately starts executing
///     IPA protocol.
/// - When helper party is done, it holds onto the results of the computation until the external party
///     that initiated this request asks for them.
///
/// [`AdditiveShare`]: crate::secret_sharing::replicated::semi_honest::AdditiveShare
pub struct Processor {
    queries: RunningQueries,
    key_registry: Arc<KeyRegistry<PrivateKeyOnly>>,
    active_work: Option<NonZeroU32PowerOfTwo>,
    runtime: IpaRuntime,
}

impl Default for Processor {
    fn default() -> Self {
        Self {
            queries: RunningQueries::default(),
            key_registry: Arc::new(KeyRegistry::<PrivateKeyOnly>::empty()),
            active_work: None,
            runtime: IpaRuntime::current(),
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum NewQueryError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    MpcTransport(#[from] MpcTransportError),
}

#[derive(thiserror::Error, Debug)]
pub enum PrepareQueryError {
    #[error("This helper is the query coordinator, cannot respond to Prepare requests")]
    WrongTarget,
    #[error("Query is already running")]
    AlreadyRunning,
    #[error(transparent)]
    StateError {
        #[from]
        source: StateError,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum QueryInputError {
    #[error("The query with id {0:?} does not exist")]
    NoSuchQuery(QueryId),
    #[error(transparent)]
    StateError {
        #[from]
        source: StateError,
    },
}

#[derive(thiserror::Error, Debug)]
pub enum QueryStatusError {
    #[error("The query with id {0:?} does not exist")]
    NoSuchQuery(QueryId),
}

#[derive(thiserror::Error, Debug)]
pub enum QueryCompletionError {
    #[error("The query with id {0:?} does not exist")]
    NoSuchQuery(QueryId),
    #[error(transparent)]
    StateError {
        #[from]
        source: StateError,
    },
    #[error("query execution failed: {0}")]
    ExecutionError(#[from] ProtocolError),
}

impl Debug for Processor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QueryProcessor[{:?}]", self.queries)
    }
}

impl Processor {
    #[must_use]
    pub fn new(
        key_registry: KeyRegistry<PrivateKeyOnly>,
        active_work: Option<NonZeroU32PowerOfTwo>,
        runtime: IpaRuntime,
    ) -> Self {
        Self {
            queries: RunningQueries::default(),
            key_registry: Arc::new(key_registry),
            active_work,
            runtime,
        }
    }

    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring.
    ///     Helper that received new query request becomes `Role::H1` (aka coordinator).
    ///     The coordinator is in theory free to choose helpers for `Role::H2` and `Role::H3`
    ///         arbitrarily (aka followers), however, this is not currently exercised.
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration
    ///     (query id, query type, field type, roles -> endpoints or reverse)
    ///         to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    ///
    /// ## Errors
    /// When other peers failed to acknowledge this query
    #[allow(clippy::missing_panics_doc)]
    pub async fn new_query(
        &self,
        transport: MpcTransportImpl,
        req: QueryConfig,
    ) -> Result<PrepareQuery, NewQueryError> {
        let query_id = QueryId;
        let handle = self.queries.handle(query_id);
        handle.set_state(QueryState::Preparing(req))?;
        let guard = handle.remove_query_on_drop();

        let id = transport.identity();
        let [right, left] = id.others();

        let roles = RoleAssignment::try_from([(id, Role::H1), (right, Role::H2), (left, Role::H3)])
            .unwrap();

        let prepare_request = PrepareQuery {
            query_id,
            config: req,
            roles: roles.clone(),
        };

        // Inform other parties about new query. If any of them rejects it, this join will fail
        try_join(
            transport.send(left, prepare_request.clone(), stream::empty()),
            transport.send(right, prepare_request.clone(), stream::empty()),
        )
        .await
        .map_err(NewQueryError::MpcTransport)?;

        handle.set_state(QueryState::AwaitingInputs(query_id, req, roles))?;

        guard.restore();
        Ok(prepare_request)
    }

    /// On prepare, each follower:
    /// * ensures that it is not the leader on this query
    /// * query is not registered yet
    /// * creates gateway and network
    /// * registers query
    ///
    /// ## Errors
    /// if query is already running or this helper cannot be a follower in it
    pub fn prepare(
        &self,
        transport: &MpcTransportImpl,
        req: PrepareQuery,
    ) -> Result<(), PrepareQueryError> {
        let my_role = req.roles.role(transport.identity());

        if my_role == Role::H1 {
            return Err(PrepareQueryError::WrongTarget);
        }
        let handle = self.queries.handle(req.query_id);
        if handle.status().is_some() {
            return Err(PrepareQueryError::AlreadyRunning);
        }

        handle.set_state(QueryState::AwaitingInputs(
            req.query_id,
            req.config,
            req.roles,
        ))?;

        Ok(())
    }

    /// Receive inputs for the specified query. That triggers query processing
    ///
    /// ## Errors
    /// if query is not registered on this helper.
    ///
    /// ## Panics
    /// If failed to obtain exclusive access to the query collection.
    pub fn receive_inputs(
        &self,
        mpc_transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
        input: QueryInput,
    ) -> Result<(), QueryInputError> {
        let mut queries = self.queries.inner.lock().unwrap();
        match queries.entry(input.query_id) {
            Entry::Occupied(entry) => {
                let state = entry.remove();
                if let QueryState::AwaitingInputs(query_id, config, role_assignment) = state {
                    assert_eq!(
                        input.query_id, query_id,
                        "received inputs for a different query"
                    );
                    let mut gateway_config = GatewayConfig::default();
                    if let Some(active_work) = self.active_work {
                        gateway_config.active = active_work;
                    } else {
                        gateway_config.set_active_work_from_query_config(&config);
                    }
                    let gateway = Gateway::new(
                        query_id,
                        gateway_config,
                        role_assignment,
                        mpc_transport,
                        shard_transport,
                    );
                    queries.insert(
                        input.query_id,
                        QueryState::Running(executor::execute(
                            &self.runtime,
                            config,
                            Arc::clone(&self.key_registry),
                            gateway,
                            input.input_stream,
                        )),
                    );
                    Ok(())
                } else {
                    let error = StateError::InvalidState {
                        from: QueryStatus::from(&state),
                        to: QueryStatus::Running,
                    };
                    queries.insert(input.query_id, state);
                    Err(QueryInputError::StateError { source: error })
                }
            }
            Entry::Vacant(_) => Err(QueryInputError::NoSuchQuery(input.query_id)),
        }
    }

    /// Returns the query status.
    ///
    /// ## Errors
    /// If query is not registered on this helper.
    ///
    /// ## Panics
    /// If the query collection mutex is poisoned.
    pub fn query_status(&self, query_id: QueryId) -> Result<QueryStatus, QueryStatusError> {
        let mut queries = self.queries.inner.lock().unwrap();
        let Some(mut state) = queries.remove(&query_id) else {
            return Err(QueryStatusError::NoSuchQuery(query_id));
        };

        if let QueryState::Running(ref mut running) = state {
            if let Some(result) = running.try_complete() {
                state = QueryState::Completed(result);
            }
        }

        let status = QueryStatus::from(&state);
        queries.insert(query_id, state);
        Ok(status)
    }

    /// Awaits the query completion
    ///
    /// ## Errors
    /// if query is not registered on this helper.
    ///
    /// ## Panics
    /// If failed to obtain exclusive access to the query collection.
    pub async fn complete(
        &self,
        query_id: QueryId,
    ) -> Result<Box<dyn ProtocolResult>, QueryCompletionError> {
        let handle = {
            let mut queries = self.queries.inner.lock().unwrap();

            match queries.remove(&query_id) {
                Some(QueryState::Completed(result)) => return result.map_err(Into::into),
                Some(QueryState::Running(handle)) => {
                    queries.insert(query_id, QueryState::AwaitingCompletion);
                    CompletionHandle::new(RemoveQuery::new(query_id, &self.queries), handle)
                }
                Some(state) => {
                    let state_error = StateError::InvalidState {
                        from: QueryStatus::from(&state),
                        to: QueryStatus::Running,
                    };
                    queries.insert(query_id, state);
                    return Err(QueryCompletionError::StateError {
                        source: state_error,
                    });
                }
                None => return Err(QueryCompletionError::NoSuchQuery(query_id)),
            }
        }; // release mutex before await

        Ok(handle.await?)
    }

    /// Terminates a query with the given id. If query is running, then it
    /// is unregistered and its task is terminated.
    ///
    /// ## Errors
    /// if query is not registered on this helper.
    ///
    /// ## Panics
    /// If failed to obtain exclusive access to the query collection.
    pub fn kill(&self, query_id: QueryId) -> Result<QueryKilled, QueryKillStatus> {
        let mut queries = self.queries.inner.lock().unwrap();
        let Some(state) = queries.remove(&query_id) else {
            return Err(QueryKillStatus::NoSuchQuery(query_id));
        };

        if let QueryState::Running(handle) = state {
            handle.join_handle.abort();
        }

        Ok(QueryKilled(query_id))
    }
}

#[derive(Clone, Serialize)]
pub struct QueryKilled(pub QueryId);

#[derive(thiserror::Error, Debug)]
pub enum QueryKillStatus {
    #[error("failed to kill a query: {0} does not exist.")]
    NoSuchQuery(QueryId),
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{array, future::Future, sync::Arc};

    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use tokio::sync::Barrier;

    use crate::{
        ff::FieldType,
        helpers::{
            make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            ApiError, HandlerBox, HelperIdentity, HelperResponse, InMemoryMpcNetwork,
            RequestHandler, RoleAssignment, Transport,
        },
        protocol::QueryId,
        query::{
            processor::Processor, state::StateError, NewQueryError, PrepareQueryError, QueryStatus,
        },
    };

    fn prepare_query_handler<F, Fut>(cb: F) -> Arc<dyn RequestHandler<HelperIdentity>>
    where
        F: Fn(PrepareQuery) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HelperResponse, ApiError>> + Send + Sync + 'static,
    {
        make_owned_handler(move |req, _| {
            let prepare_query = req.into().unwrap();
            cb(prepare_query)
        })
    }

    fn respond_ok() -> Arc<dyn RequestHandler<HelperIdentity>> {
        prepare_query_handler(move |_| async move { Ok(HelperResponse::ok()) })
    }

    fn test_multiply_config() -> QueryConfig {
        QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap()
    }

    #[tokio::test]
    async fn new_query() {
        let barrier = Arc::new(Barrier::new(3));
        let h2_barrier = Arc::clone(&barrier);
        let h3_barrier = Arc::clone(&barrier);
        let h2 = prepare_query_handler(move |_| {
            let barrier = Arc::clone(&h2_barrier);
            async move {
                barrier.wait().await;
                Ok(HelperResponse::ok())
            }
        });
        let h3 = prepare_query_handler(move |_| {
            let barrier = Arc::clone(&h3_barrier);
            async move {
                barrier.wait().await;
                Ok(HelperResponse::ok())
            }
        });
        let network = InMemoryMpcNetwork::new([
            None,
            Some(HandlerBox::owning_ref(&h2)),
            Some(HandlerBox::owning_ref(&h3)),
        ]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = test_multiply_config();

        let qc_future = p0.new_query(t0, request);
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let _qc = poll_immediate(&mut qc_future).await;

        assert_eq!(QueryStatus::Preparing, p0.query_status(QueryId).unwrap());
        // unblock sends
        barrier.wait().await;

        let qc = qc_future.await.unwrap();
        let expected_assignment = RoleAssignment::new(HelperIdentity::make_three());

        assert_eq!(
            PrepareQuery {
                query_id: QueryId,
                config: request,
                roles: expected_assignment,
            },
            qc
        );
        assert_eq!(
            QueryStatus::AwaitingInputs,
            p0.query_status(QueryId).unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let handlers =
            array::from_fn(|_| prepare_query_handler(|_| async { Ok(HelperResponse::ok()) }));
        let network =
            InMemoryMpcNetwork::new(handlers.each_ref().map(HandlerBox::owning_ref).map(Some));
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = test_multiply_config();

        let _qc = p0
            .new_query(Transport::clone_ref(&t0), request)
            .await
            .unwrap();
        assert!(matches!(
            p0.new_query(t0, request).await,
            Err(NewQueryError::State(StateError::AlreadyRunning)),
        ));
    }

    #[tokio::test]
    async fn prepare_error() {
        let h2 = respond_ok();
        let h3 = prepare_query_handler(|_| async move {
            Err(ApiError::QueryPrepare(PrepareQueryError::WrongTarget))
        });
        let network = InMemoryMpcNetwork::new([
            None,
            Some(HandlerBox::owning_ref(&h2)),
            Some(HandlerBox::owning_ref(&h3)),
        ]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = test_multiply_config();

        assert!(matches!(
            p0.new_query(t0, request).await.unwrap_err(),
            NewQueryError::MpcTransport(_)
        ));
    }

    #[tokio::test]
    async fn can_recover_from_prepare_error() {
        let h2 = respond_ok();
        let h3 = prepare_query_handler(|_| async move {
            Err(ApiError::QueryPrepare(PrepareQueryError::WrongTarget))
        });
        let network = InMemoryMpcNetwork::new([
            None,
            Some(HandlerBox::owning_ref(&h2)),
            Some(HandlerBox::owning_ref(&h3)),
        ]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = test_multiply_config();
        p0.new_query(t0.clone_ref(), request).await.unwrap_err();

        assert!(matches!(
            p0.new_query(t0, request).await.unwrap_err(),
            NewQueryError::MpcTransport(_)
        ));
    }

    mod prepare {
        use super::*;
        use crate::query::QueryStatusError;

        fn prepare_query(identities: [HelperIdentity; 3]) -> PrepareQuery {
            PrepareQuery {
                query_id: QueryId,
                config: test_multiply_config(),
                roles: RoleAssignment::new(identities),
            }
        }

        #[tokio::test]
        async fn happy_case() {
            let network = InMemoryMpcNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(identities);
            let transport = network.transport(identities[1]);
            let processor = Processor::default();

            assert!(matches!(
                processor.query_status(QueryId).unwrap_err(),
                QueryStatusError::NoSuchQuery(_)
            ));
            processor.prepare(&transport, req).unwrap();
            assert_eq!(
                QueryStatus::AwaitingInputs,
                processor.query_status(QueryId).unwrap()
            );
        }

        #[tokio::test]
        async fn rejects_if_coordinator() {
            let network = InMemoryMpcNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(identities);
            let transport = network.transport(identities[0]);
            let processor = Processor::default();

            assert!(matches!(
                processor.prepare(&transport, req),
                Err(PrepareQueryError::WrongTarget)
            ));
        }

        #[tokio::test]
        async fn rejects_if_query_exists() {
            let network = InMemoryMpcNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(identities);
            let transport = network.transport(identities[1]);
            let processor = Processor::default();
            processor.prepare(&transport, req.clone()).unwrap();
            assert!(matches!(
                processor.prepare(&transport, req),
                Err(PrepareQueryError::AlreadyRunning)
            ));
        }
    }

    mod kill {
        use std::sync::Arc;

        use crate::{
            executor::IpaRuntime,
            ff::FieldType,
            helpers::{
                query::{
                    QueryConfig,
                    QueryType::{TestAddInPrimeField, TestMultiply},
                },
                HandlerBox, HelperIdentity, InMemoryMpcNetwork, Transport,
            },
            protocol::QueryId,
            query::{
                processor::{tests::respond_ok, Processor},
                state::{QueryState, RunningQuery},
                QueryKillStatus,
            },
            test_executor::run,
        };

        #[test]
        fn non_existent_query() {
            run(|| async {
                let processor = Processor::default();
                assert!(matches!(
                    processor.kill(QueryId),
                    Err(QueryKillStatus::NoSuchQuery(QueryId))
                ));
            });
        }

        #[test]
        fn existing_query() {
            run(|| async move {
                let h2 = respond_ok();
                let h3 = respond_ok();
                let network = InMemoryMpcNetwork::new([
                    None,
                    Some(HandlerBox::owning_ref(&h2)),
                    Some(HandlerBox::owning_ref(&h3)),
                ]);
                let identities = HelperIdentity::make_three();
                let processor = Processor::default();
                let transport = network.transport(identities[0]);
                processor
                    .new_query(
                        Transport::clone_ref(&transport),
                        QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap(),
                    )
                    .await
                    .unwrap();

                processor.kill(QueryId).unwrap();

                // start query again - it should work because the query was killed
                processor
                    .new_query(
                        transport,
                        QueryConfig::new(TestAddInPrimeField, FieldType::Fp32BitPrime, 1).unwrap(),
                    )
                    .await
                    .unwrap();
            });
        }

        #[test]
        fn aborts_protocol_task() {
            run(|| async move {
                let processor = Processor::default();
                let (_tx, rx) = tokio::sync::oneshot::channel();
                let counter = Arc::new(1);
                let task = IpaRuntime::current().spawn({
                    let counter = Arc::clone(&counter);
                    async move {
                        loop {
                            tokio::task::yield_now().await;
                            let _ = *counter.as_ref();
                        }
                    }
                });
                processor.queries.inner.lock().unwrap().insert(
                    QueryId,
                    QueryState::Running(RunningQuery {
                        result: rx,
                        join_handle: task,
                    }),
                );

                assert_eq!(2, Arc::strong_count(&counter));
                processor.kill(QueryId).unwrap();
                while Arc::strong_count(&counter) > 1 {
                    tokio::task::yield_now().await;
                }
            });
        }
    }

    mod e2e {
        use std::time::Duration;

        use tokio::time::sleep;

        use super::*;
        use crate::{
            error::BoxError,
            ff::{
                boolean_array::{BA20, BA3, BA8},
                Fp31, U128Conversions,
            },
            helpers::query::{IpaQueryConfig, QueryType},
            protocol::ipa_prf::OPRFIPAInputRow,
            secret_sharing::replicated::semi_honest,
            test_fixture::{ipa::TestRawDataRecord, Reconstruct, TestApp},
        };

        #[tokio::test]
        async fn complete_query_test_multiply() -> Result<(), BoxError> {
            let app = TestApp::default();
            let a = Fp31::truncate_from(4u128);
            let b = Fp31::truncate_from(5u128);
            let results = app
                .execute_query(vec![a, b].into_iter(), test_multiply_config())
                .await?;

            let results = results.map(|bytes| {
                semi_honest::AdditiveShare::<Fp31>::from_byte_slice(&bytes)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
            });

            Ok(assert_eq!(
                vec![Fp31::truncate_from(20u128)],
                results.reconstruct()
            ))
        }

        #[tokio::test]
        async fn complete_query_status_poll() -> Result<(), BoxError> {
            let app = TestApp::default();
            let a = Fp31::truncate_from(4u128);
            let b = Fp31::truncate_from(5u128);
            let query_id = app
                .start_query(vec![a, b].into_iter(), test_multiply_config())
                .await?;

            while !app
                .query_status(query_id)?
                .into_iter()
                .all(|s| s == QueryStatus::Completed)
            {
                sleep(Duration::from_millis(1)).await;
            }

            let results = app.complete_query(query_id).await?.map(|bytes| {
                semi_honest::AdditiveShare::<Fp31>::from_byte_slice_unchecked(&bytes)
                    .collect::<Vec<_>>()
            });

            Ok(assert_eq!(
                &[Fp31::truncate_from(20u128)] as &[_],
                results.reconstruct()
            ))
        }

        #[tokio::test]
        async fn complete_query_ipa() -> Result<(), BoxError> {
            let app = TestApp::default();
            ipa_query(&app).await
        }

        #[tokio::test]
        async fn complete_query_twice() -> Result<(), BoxError> {
            let app = TestApp::default();
            ipa_query(&app).await?;
            ipa_query(&app).await
        }

        async fn ipa_query(app: &TestApp) -> Result<(), BoxError> {
            let records = vec![
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 12345,
                    is_trigger_report: false,
                    breakdown_key: 2,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 68362,
                    is_trigger_report: false,
                    breakdown_key: 1,
                    trigger_value: 0,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 12345,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 5,
                },
                TestRawDataRecord {
                    timestamp: 0,
                    user_id: 68362,
                    is_trigger_report: true,
                    breakdown_key: 0,
                    trigger_value: 2,
                },
            ];
            let record_count = records.len();

            let _results = app
                // Achtung: OPRF IPA executor assumes BA8, BA3, BA20 to be the encodings of
                // inputs - using anything else will lead to a padding error.
                .execute_query::<_, Vec<OPRFIPAInputRow<BA8, BA3, BA20>>>(
                    records.into_iter(),
                    QueryConfig {
                        size: record_count.try_into().unwrap(),
                        field_type: FieldType::Fp31,
                        query_type: QueryType::SemiHonestOprfIpa(IpaQueryConfig {
                            per_user_credit_cap: 8,
                            max_breakdown_key: 3,
                            attribution_window_seconds: None,
                            with_dp: 0,
                            epsilon: 5.0,
                            plaintext_match_keys: true,
                        }),
                    },
                )
                .await?;

            Ok(())
        }
    }
}
