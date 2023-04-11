use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        Gateway, GatewayConfig, Role, RoleAssignment, Transport, TransportError, TransportImpl,
    },
    protocol::QueryId,
    query::{
        executor,
        state::{QueryState, QueryStatus, RunningQueries, StateError},
        ProtocolResult,
    },
};

use futures_util::{future::try_join, stream};

use std::{
    borrow::Borrow,
    collections::hash_map::Entry,
    fmt::{Debug, Formatter},
};
use tokio::sync::oneshot;

/// `Processor` accepts and tracks requests to initiate new queries on this helper party
/// network. It makes sure queries are coordinated and each party starts processing it when
/// it has all the information required.
///
/// Query processing consists of multiple steps:
/// - A new request to initiate a query arrives from an external party (report collector) to any of the
/// helpers.
/// - Upon receiving that request, helper chooses a unique [`QueryId`] and assigns [`Role`] to every
/// helper. It informs other parties about it and awaits their response.
/// - If all parties accept the proposed query, they negotiate shared randomness and signal that
/// - they're ready to receive inputs.
/// - Each party, upon receiving the input as a set of [`AdditiveShare`], immediately starts executing
/// IPA protocol.
/// - When helper party is done, it holds onto the results of the computation until the external party
/// that initiated this request asks for them.
///
/// [`AdditiveShare`]: crate::secret_sharing::replicated::semi_honest::AdditiveShare
#[derive(Default)]
pub struct Processor {
    queries: RunningQueries,
}

#[derive(thiserror::Error, Debug)]
pub enum NewQueryError {
    #[error(transparent)]
    State(#[from] StateError),
    #[error(transparent)]
    Transport(#[from] TransportError),
    #[error(transparent)]
    OneshotRecv(#[from] oneshot::error::RecvError),
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
pub enum QueryCompletionError {
    #[error("The query with id {0:?} does not exist")]
    NoSuchQuery(QueryId),
    #[error(transparent)]
    StateError {
        #[from]
        source: StateError,
    },
}

impl Debug for Processor {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QueryProcessor[{:?}]", self.queries)
    }
}

impl Processor {
    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka coordinator).
    /// The coordinator is in theory free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers), however, this is not currently exercised.
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    ///
    /// ## Errors
    /// When other peers failed to acknowledge this query
    #[allow(clippy::missing_panics_doc)]
    pub async fn new_query<T: Transport>(
        &self,
        transport: &T,
        req: QueryConfig,
    ) -> Result<PrepareQuery, NewQueryError> {
        let query_id = QueryId;
        let handle = self.queries.handle(query_id);
        handle.set_state(QueryState::Preparing(req))?;
        let transport = transport.borrow();

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
            transport.send(left, &prepare_request, stream::empty()),
            transport.send(right, &prepare_request, stream::empty()),
        )
        .await?;

        handle.set_state(QueryState::AwaitingInputs(query_id, req, roles))?;

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
    pub fn prepare<T: Transport>(
        &self,
        transport: &T,
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
    /// If failed to obtain an exclusive access to the query collection.
    pub fn receive_inputs(
        &self,
        transport: TransportImpl,
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
                    let gateway = Gateway::new(
                        query_id,
                        GatewayConfig::default(),
                        role_assignment,
                        transport,
                    );
                    queries.insert(
                        input.query_id,
                        QueryState::Running(executor::start_query(
                            config,
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

    pub fn status(&self, query_id: QueryId) -> Option<QueryStatus> {
        self.queries.handle(query_id).status()
    }

    /// Awaits the query completion
    ///
    /// ## Errors
    /// if query is not registered on this helper.
    ///
    /// ## Panics
    /// If failed to obtain an exclusive access to the query collection.
    pub async fn complete(
        &self,
        query_id: QueryId,
    ) -> Result<Box<dyn ProtocolResult>, QueryCompletionError> {
        let handle = {
            let mut queries = self.queries.inner.lock().unwrap();

            match queries.remove(&query_id) {
                Some(QueryState::Running(handle)) => {
                    queries.insert(query_id, QueryState::AwaitingCompletion);
                    Ok(handle)
                }
                Some(state) => {
                    let state_error = StateError::InvalidState {
                        from: QueryStatus::from(&state),
                        to: QueryStatus::Running,
                    };
                    queries.insert(query_id, state);
                    Err(QueryCompletionError::StateError {
                        source: state_error,
                    })
                }
                None => Err(QueryCompletionError::NoSuchQuery(query_id)),
            }
        }?;

        Ok(handle.await.unwrap())
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::FieldType,
        helpers::{query::QueryType, HelperIdentity, PrepareQueryCallback, TransportCallbacks},
        test_fixture::network::InMemoryNetwork,
    };
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use std::{future::Future, sync::Arc};
    use tokio::sync::Barrier;

    fn prepare_query_callback<'a, T, F, Fut>(cb: F) -> Box<dyn PrepareQueryCallback<T>>
    where
        F: Fn(T, PrepareQuery) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<(), TransportError>> + Send + 'static,
    {
        Box::new(move |transport, prepare_query| Box::pin(cb(transport, prepare_query)))
    }

    #[tokio::test]
    async fn new_query() {
        let barrier = Arc::new(Barrier::new(3));
        let cb2_barrier = Arc::clone(&barrier);
        let cb3_barrier = Arc::clone(&barrier);
        let cb2 = TransportCallbacks {
            prepare_query: prepare_query_callback(move |_, _| {
                let barrier = Arc::clone(&cb2_barrier);
                async move {
                    barrier.wait().await;
                    Ok(())
                }
            }),
            ..Default::default()
        };
        let cb3 = TransportCallbacks {
            prepare_query: prepare_query_callback(move |_, _| {
                let barrier = Arc::clone(&cb3_barrier);
                async move {
                    barrier.wait().await;
                    Ok(())
                }
            }),
            ..Default::default()
        };
        let network = InMemoryNetwork::new([TransportCallbacks::default(), cb2, cb3]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = QueryConfig::default();

        let qc_future = p0.new_query(&t0, request);
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let _qc = poll_immediate(&mut qc_future).await;

        assert_eq!(Some(QueryStatus::Preparing), p0.status(QueryId));
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
        assert_eq!(Some(QueryStatus::AwaitingInputs), p0.status(QueryId));
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let network = InMemoryNetwork::new([
            TransportCallbacks::default(),
            TransportCallbacks::default(),
            TransportCallbacks::default(),
        ]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = QueryConfig::default();

        let _qc = p0.new_query(&t0, request).await.unwrap();
        assert!(matches!(
            p0.new_query(&t0, request).await,
            Err(NewQueryError::State(StateError::AlreadyRunning)),
        ));
    }

    #[tokio::test]
    async fn prepare_rejected() {
        let cb2 = TransportCallbacks {
            prepare_query: prepare_query_callback(|_, _| async { Ok(()) }),
            ..Default::default()
        };
        let cb3 = TransportCallbacks {
            prepare_query: prepare_query_callback(|_, _| async {
                Err(TransportError::Rejected {
                    dest: HelperIdentity::THREE,
                    inner: "rejected".into(),
                })
            }),
            ..Default::default()
        };
        let network = InMemoryNetwork::new([TransportCallbacks::default(), cb2, cb3]);
        let [t0, _, _] = network.transports();
        let p0 = Processor::default();
        let request = QueryConfig::default();

        assert!(matches!(
            p0.new_query(&t0, request).await.unwrap_err(),
            NewQueryError::Transport(_)
        ));
    }

    mod prepare {
        use super::*;

        fn prepare_query(identities: [HelperIdentity; 3]) -> PrepareQuery {
            PrepareQuery {
                query_id: QueryId,
                config: QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                },
                roles: RoleAssignment::new(identities),
            }
        }

        #[tokio::test]
        async fn happy_case() {
            let network = InMemoryNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(identities);
            let transport = network.transport(identities[1]);
            let processor = Processor::default();

            assert_eq!(None, processor.status(QueryId));
            processor.prepare(&transport, req).unwrap();
            assert_eq!(Some(QueryStatus::AwaitingInputs), processor.status(QueryId));
        }

        #[tokio::test]
        async fn rejects_if_coordinator() {
            let network = InMemoryNetwork::default();
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
            let network = InMemoryNetwork::default();
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

    mod e2e {
        use super::*;
        use crate::{
            error::BoxError,
            ff::{Field, Fp31},
            helpers::query::IpaQueryConfig,
            ipa_test_input,
            protocol::{ipa::IPAInputRow, BreakdownKey, MatchKey},
            secret_sharing::replicated::semi_honest,
            test_fixture::{input::GenericReportTestInput, Reconstruct, TestApp},
        };

        #[tokio::test]
        async fn complete_query_test_multiply() -> Result<(), BoxError> {
            let app = TestApp::default();
            let a = Fp31::truncate_from(4u128);
            let b = Fp31::truncate_from(5u128);
            let results = app
                .execute_query(
                    vec![a, b],
                    QueryConfig {
                        field_type: FieldType::Fp31,
                        query_type: QueryType::TestMultiply,
                    },
                )
                .await?;

            let results = results.map(|bytes| {
                semi_honest::AdditiveShare::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
            });

            Ok(assert_eq!(
                vec![Fp31::truncate_from(20u128)],
                results.reconstruct()
            ))
        }

        #[tokio::test]
        async fn complete_query_ipa() -> Result<(), BoxError> {
            let app = TestApp::default();
            let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
                [
                    { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                    { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                    { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                    { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                    { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
                ];
                (Fp31, MatchKey, BreakdownKey)
            );
            let _results = app
                .execute_query::<_, Vec<IPAInputRow<_, _, _>>>(
                    records,
                    QueryConfig {
                        field_type: FieldType::Fp31,
                        query_type: QueryType::Ipa(IpaQueryConfig {
                            per_user_credit_cap: 3,
                            max_breakdown_key: 3,
                            attribution_window_seconds: 0,
                            num_multi_bits: 3,
                        }),
                    },
                )
                .await?;

            Ok(())
        }
    }
}
