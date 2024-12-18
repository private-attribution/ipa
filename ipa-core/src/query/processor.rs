use std::{
    collections::hash_map::Entry,
    fmt::{Debug, Formatter},
};

use futures::{future::try_join, stream};
use serde::Serialize;

use super::min_status;
use crate::{
    error::Error as ProtocolError,
    executor::IpaRuntime,
    helpers::{
        query::{CompareStatusRequest, PrepareQuery, QueryConfig},
        routing::RouteId,
        BodyStream, BroadcastError, Gateway, GatewayConfig, MpcTransportError, MpcTransportImpl,
        Role, RoleAssignment, ShardTransportError, ShardTransportImpl, Transport,
    },
    hpke::{KeyRegistry, PrivateKeyOnly},
    protocol::QueryId,
    query::{
        executor,
        state::{QueryState, QueryStatus, RemoveQuery, RunningQueries, StateError},
        CompletionHandle, ProtocolResult,
    },
    sharding::ShardIndex,
    sync::Arc,
    utils::NonZeroU32PowerOfTwo,
};

/// [`Processor`] accepts and tracks requests to initiate new queries on this helper party
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
/// This struct is decoupled from the [`Transport`]s used to communicate with other [`Processor`]
/// running in other shards or helpers. Many functions require transport as part of their arguments
/// to communicate with its peers. The transports also identify this [`Processor`] in the network so
/// it's important to remain consistent on the transports given as parameters.
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
    #[error(transparent)]
    ShardBroadcastError(#[from] BroadcastError<ShardIndex, ShardTransportError>),
}

#[derive(thiserror::Error, Debug)]
pub enum PrepareQueryError {
    #[error("This helper is the query coordinator, cannot respond to Prepare requests")]
    WrongTarget,
    #[error("This shard {0:?} isn't the leader (shard 0)")]
    NotLeader(ShardIndex),
    #[error("This is the leader shard")]
    Leader,
    #[error("Query is already running")]
    AlreadyRunning,
    #[error(transparent)]
    StateError {
        #[from]
        source: StateError,
    },
    #[error(transparent)]
    ShardBroadcastError(#[from] BroadcastError<ShardIndex, ShardTransportError>),
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
    #[error(transparent)]
    ShardBroadcastError(#[from] BroadcastError<ShardIndex, ShardTransportError>),
    #[error("This shard {0:?} isn't the leader (shard 0)")]
    NotLeader(ShardIndex),
    #[error("This is the leader shard")]
    Leader,
    #[error("My status {my_status:?} for query {query_id:?} differs from {other_status:?}")]
    DifferentStatus {
        query_id: QueryId,
        my_status: QueryStatus,
        other_status: QueryStatus,
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
    #[error("query execution failed: {0}")]
    ExecutionError(#[from] ProtocolError),
    #[error("one or more shards rejected this request: {0}")]
    ShardError(#[from] BroadcastError<ShardIndex, ShardTransportError>),
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
    ///         to helpers and its shards and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    ///
    /// ## Errors
    /// When other peers failed to acknowledge this query
    #[allow(clippy::missing_panics_doc)]
    pub async fn new_query(
        &self,
        transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
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
        // Inform other helpers about new query. If any of them rejects it, this join will fail
        // TODO: If H2 succeeds and H3 fails, we need to rollback H2.
        try_join(
            transport.send(left, prepare_request.clone(), stream::empty()),
            transport.send(right, prepare_request.clone(), stream::empty()),
        )
        .await
        .map_err(NewQueryError::MpcTransport)?;

        // TODO: Similar to the todo above. If shards 1,2 and 3 succeed but 4 fails, then we need
        // to rollback 1,2 and 3
        shard_transport.broadcast(prepare_request.clone()).await?;

        handle.set_state(QueryState::AwaitingInputs(req, roles))?;

        guard.restore();
        Ok(prepare_request)
    }

    /// On prepare, each leader:
    /// * ensures that it is not the leader helper on this query
    /// * query is not registered yet
    /// * registers query
    ///
    /// ## Errors
    /// if query is already running or this helper cannot be a follower in it
    pub async fn prepare_helper(
        &self,
        mpc_transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
        req: PrepareQuery,
    ) -> Result<(), PrepareQueryError> {
        let my_role = req.roles.role(mpc_transport.identity());
        let shard_index = shard_transport.identity();

        if my_role == Role::H1 {
            return Err(PrepareQueryError::WrongTarget);
        }
        if shard_index != ShardIndex::FIRST {
            return Err(PrepareQueryError::NotLeader(shard_index));
        }
        let handle = self.queries.handle(req.query_id);
        if handle.status().is_some() {
            return Err(PrepareQueryError::AlreadyRunning);
        }

        // TODO: If shards 1,2 and 3 succeed but 4 fails, then we need to rollback 1,2 and 3.
        shard_transport.broadcast(req.clone()).await?;

        handle.set_state(QueryState::AwaitingInputs(req.config, req.roles))?;

        Ok(())
    }

    /// On prepare, each shard:
    /// * ensures that it is not the leader on this query
    /// * query is not registered yet
    /// * registers query
    ///
    /// ## Errors
    /// if query is already running or this helper cannot be a follower in it
    pub fn prepare_shard(
        &self,
        shard_transport: &ShardTransportImpl,
        req: PrepareQuery,
    ) -> Result<(), PrepareQueryError> {
        let shard_index = shard_transport.identity();
        if shard_index == ShardIndex::FIRST {
            return Err(PrepareQueryError::Leader);
        }

        let handle = self.queries.handle(req.query_id);
        if handle.status().is_some() {
            return Err(PrepareQueryError::AlreadyRunning);
        }

        handle.set_state(QueryState::AwaitingInputs(req.config, req.roles))?;

        Ok(())
    }

    /// Receive inputs for the specified query and creates gateway and network
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
        query_id: QueryId,
        input_stream: BodyStream,
    ) -> Result<(), QueryInputError> {
        let mut queries = self.queries.inner.lock().unwrap();
        match queries.entry(query_id) {
            Entry::Occupied(entry) => {
                let state = entry.remove();
                if let QueryState::AwaitingInputs(config, role_assignment) = state {
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
                        query_id,
                        QueryState::Running(executor::execute(
                            &self.runtime,
                            config,
                            Arc::clone(&self.key_registry),
                            gateway,
                            input_stream,
                        )),
                    );
                    Ok(())
                } else {
                    let error = StateError::InvalidState {
                        from: QueryStatus::from(&state),
                        to: QueryStatus::Running,
                    };
                    queries.insert(query_id, state);
                    Err(QueryInputError::StateError { source: error })
                }
            }
            Entry::Vacant(_) => Err(QueryInputError::NoSuchQuery(query_id)),
        }
    }

    /// Returns the status of the running query or [`None`].
    /// If the query was completed it updates the state to reflect that.
    fn get_status(&self, query_id: QueryId) -> Option<QueryStatus> {
        let mut queries = self.queries.inner.lock().unwrap();
        let mut state = queries.remove(&query_id)?;

        if let QueryState::Running(ref mut running) = state {
            if let Some(result) = running.try_complete() {
                state = QueryState::Completed(result);
            }
        }

        let status = QueryStatus::from(&state);
        queries.insert(query_id, state);
        Some(status)
    }

    /// This helper function is used to transform a [`BoxError`] into a
    /// [`QueryStatusError::DifferentStatus`] and retrieve it's internal state. Returns [`None`]
    /// if not possible.
    #[cfg(feature = "in-memory-infra")]
    fn downcast_state_error(box_error: &crate::error::BoxError) -> Option<QueryStatus> {
        use crate::helpers::ApiError;
        let api_error = box_error.downcast_ref::<ApiError>();
        if let Some(ApiError::QueryStatus(QueryStatusError::DifferentStatus {
            my_status, ..
        })) = api_error
        {
            return Some(*my_status);
        }
        None
    }

    /// This helper is used by the in-memory stack to obtain the state of other shards via a
    /// [`QueryStatusError::DifferentStatus`] error.
    /// TODO: Ideally broadcast should return a value, that we could use to parse the state instead
    /// of relying on errors.
    #[cfg(feature = "in-memory-infra")]
    fn get_state_from_error(
        error: &crate::helpers::InMemoryTransportError<ShardIndex>,
    ) -> Option<QueryStatus> {
        if let crate::helpers::InMemoryTransportError::Rejected { inner, .. } = error {
            return Self::downcast_state_error(inner);
        }
        None
    }

    /// This helper is used by the HTTP stack to obtain the state of other shards via a
    /// [`QueryStatusError::DifferentStatus`] error.
    /// TODO: Ideally broadcast should return a value, that we could use to parse the state instead
    /// of relying on errors.
    #[cfg(feature = "real-world-infra")]
    fn get_state_from_error(shard_error: &crate::net::ShardError) -> Option<QueryStatus> {
        if let crate::net::Error::ShardQueryStatusMismatch { error, .. } = &shard_error.source {
            return Some(error.actual);
        }
        None
    }

    /// Returns the query status in this helper, by querying all shards.
    ///
    /// ## Errors
    /// If query is not registered on this helper.
    ///
    /// ## Panics
    /// If the query collection mutex is poisoned.
    pub async fn query_status(
        &self,
        shard_transport: ShardTransportImpl,
        query_id: QueryId,
    ) -> Result<QueryStatus, QueryStatusError> {
        let shard_index = shard_transport.identity();
        if shard_index != ShardIndex::FIRST {
            return Err(QueryStatusError::NotLeader(shard_index));
        }

        let mut status = self
            .get_status(query_id)
            .ok_or(QueryStatusError::NoSuchQuery(query_id))?;

        let shard_query_status_req = CompareStatusRequest { query_id, status };

        let shard_responses = shard_transport.broadcast(shard_query_status_req).await;
        if let Err(e) = shard_responses {
            for (shard, failure) in &e.failures {
                if let Some(other) = Self::get_state_from_error(failure) {
                    status = min_status(status, other);
                } else {
                    tracing::error!("failed to get status from shard {shard}: {failure:?}");
                    return Err(e.into());
                }
            }
        }

        Ok(status)
    }

    /// Compares this shard status against the given type. Returns an error if different.
    ///
    /// ## Errors
    /// If query is not registered on this helper or
    ///
    /// ## Panics
    /// If the query collection mutex is poisoned.
    pub fn shard_status(
        &self,
        shard_transport: &ShardTransportImpl,
        req: &CompareStatusRequest,
    ) -> Result<QueryStatus, QueryStatusError> {
        let shard_index = shard_transport.identity();
        if shard_index == ShardIndex::FIRST {
            return Err(QueryStatusError::Leader);
        }
        let status = self
            .get_status(req.query_id)
            .ok_or(QueryStatusError::NoSuchQuery(req.query_id))?;
        if req.status != status {
            return Err(QueryStatusError::DifferentStatus {
                query_id: req.query_id,
                my_status: status,
                other_status: req.status,
            });
        }
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
        shard_transport: ShardTransportImpl,
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

        // Inform other shards about our intent to complete the query.
        // If any of them rejects it, report the error back. We expect all shards
        // to be in the same state. In normal cycle, this API is called only after
        // query status reports completion.
        if shard_transport.identity() == ShardIndex::FIRST {
            // See shard finalizer protocol to see how shards merge their results together.
            // At the end, only leader holds the value
            shard_transport
                .broadcast((RouteId::CompleteQuery, query_id))
                .await?;
        }

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
        executor::IpaRuntime,
        ff::{boolean_array::BA64, FieldType},
        helpers::{
            make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            routing::Addr,
            ApiError, HandlerBox, HelperIdentity, HelperResponse, InMemoryMpcNetwork,
            InMemoryShardNetwork, InMemoryTransport, RequestHandler, RoleAssignment, Transport,
            TransportIdentity,
        },
        protocol::QueryId,
        query::{
            processor::Processor,
            state::{QueryState, RunningQuery, StateError},
            NewQueryError, PrepareQueryError, QueryStatus, QueryStatusError,
        },
        sharding::ShardIndex,
    };

    fn prepare_query() -> PrepareQuery {
        PrepareQuery {
            query_id: QueryId,
            config: test_multiply_config(),
            roles: RoleAssignment::new(HelperIdentity::make_three()),
        }
    }

    fn create_handler<F, Fut, I: TransportIdentity>(cb: F) -> Arc<dyn RequestHandler<I>>
    where
        F: Fn(Addr<I>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<HelperResponse, ApiError>> + Send + Sync + 'static,
    {
        make_owned_handler(move |req, _| cb(req))
    }

    fn helper_respond_ok() -> Arc<dyn RequestHandler<HelperIdentity>> {
        create_handler(|_| async { Ok(HelperResponse::ok()) })
    }

    fn shard_respond_ok(_si: ShardIndex) -> Arc<dyn RequestHandler<ShardIndex>> {
        create_handler(|_| async { Ok(HelperResponse::ok()) })
    }

    fn test_multiply_config() -> QueryConfig {
        QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap()
    }

    struct TestComponentsArgs {
        #[allow(clippy::type_complexity)]
        opt_shards: Option<(
            InMemoryShardNetwork,
            Vec<Arc<dyn RequestHandler<ShardIndex>>>,
        )>,
        mpc_handlers: [Option<Arc<dyn RequestHandler<HelperIdentity>>>; 3],
        shard_count: u32,
    }

    impl TestComponentsArgs {
        fn new(mpc_handler: &Arc<dyn RequestHandler<HelperIdentity>>) -> Self {
            Self {
                opt_shards: None,
                mpc_handlers: array::from_fn(|_| Some(Arc::clone(mpc_handler))),
                shard_count: 2,
            }
        }

        #[allow(dead_code)]
        fn set_shard_handler<F>(&mut self, handler: F)
        where
            F: Fn(ShardIndex) -> Arc<dyn RequestHandler<ShardIndex>>,
        {
            self.opt_shards = Some(InMemoryShardNetwork::with_shards_and_handlers(
                self.shard_count,
                handler,
            ));
        }

        fn take_shards(
            &mut self,
        ) -> (
            InMemoryShardNetwork,
            Vec<Arc<dyn RequestHandler<ShardIndex>>>,
        ) {
            if let Some(shards) = self.opt_shards.take() {
                shards
            } else {
                // This method creates a network for 3 helpers but we will only use one.
                InMemoryShardNetwork::with_shards_and_handlers(self.shard_count, shard_respond_ok)
            }
        }
    }

    impl Default for TestComponentsArgs {
        fn default() -> Self {
            TestComponentsArgs::new(&helper_respond_ok())
        }
    }

    /// This struct aims to streamline unit tests that use a single [`Processor`] and mock the
    /// responses coming from the other's. Note only one [`Processor`] is ever created, not an
    /// entire MPC network. This means that if you want to test a workflow that involves multiple
    /// steps involving [`Processor`] function calls, in different helpers or shards, you will need
    /// to create multiple instances of this helper.
    ///
    /// Following is a minimal example on how to setup a single [`Processor`] for which all
    /// transport calls to either shards or helpers with simply return Ok.
    ///
    /// ```
    /// let t = TestComponents::new(TestComponentsArgs::default());
    /// t.processor.query_status(QueryId)
    /// ```
    #[allow(dead_code)]
    struct TestComponents {
        processor: Processor,
        query_config: QueryConfig,

        mpc_network: InMemoryMpcNetwork,
        first_transport: InMemoryTransport<HelperIdentity>,
        second_transport: InMemoryTransport<HelperIdentity>,
        third_transport: InMemoryTransport<HelperIdentity>,
        mpc_handlers: [Option<Arc<dyn RequestHandler<HelperIdentity>>>; 3],

        shard_network: InMemoryShardNetwork,
        shard_handlers: Vec<Arc<dyn RequestHandler<ShardIndex>>>,
        shard_transport: InMemoryTransport<ShardIndex>,
    }

    impl Default for TestComponents {
        fn default() -> Self {
            Self::new(TestComponentsArgs::default())
        }
    }

    impl TestComponents {
        const COMPLETE_QUERY_RESULT: Vec<BA64> = Vec::new();

        fn new(mut args: TestComponentsArgs) -> Self {
            let mpc_network = InMemoryMpcNetwork::new(
                args.mpc_handlers
                    .each_ref()
                    .map(|opt_h| opt_h.as_ref().map(HandlerBox::owning_ref)),
            );
            let (shard_network, shard_handlers) = args.take_shards();
            let processor = Processor::default();
            let query_config = test_multiply_config();
            let [t0, t1, t2] = mpc_network.transports();
            let shard_transport = shard_network.transport(HelperIdentity::ONE, ShardIndex::FIRST);
            TestComponents {
                processor,
                query_config,
                mpc_network,
                first_transport: t0,
                second_transport: t1,
                third_transport: t2,
                mpc_handlers: args.mpc_handlers,
                shard_network,
                shard_handlers,
                shard_transport,
            }
        }

        /// This initiates a new query on all shards and puts them all on running state.
        /// It also makes up a fake query result
        async fn new_running_query(&self) -> QueryId {
            self.processor
                .new_query(
                    self.first_transport.clone_ref(),
                    self.shard_transport.clone_ref(),
                    self.query_config,
                )
                .await
                .unwrap();
            let (tx, rx) = tokio::sync::oneshot::channel();
            self.processor
                .queries
                .handle(QueryId)
                .set_state(QueryState::Running(RunningQuery {
                    result: rx,
                    join_handle: IpaRuntime::current().spawn(async {}),
                }))
                .unwrap();
            tx.send(Ok(Box::new(Self::COMPLETE_QUERY_RESULT))).unwrap();

            QueryId
        }
    }

    #[tokio::test]
    async fn new_query() {
        let mut args = TestComponentsArgs::default();
        let barrier = Arc::new(Barrier::new(3));
        let h2_barrier = Arc::clone(&barrier);
        let h3_barrier = Arc::clone(&barrier);
        let h2 = create_handler(move |_| {
            let barrier = Arc::clone(&h2_barrier);
            async move {
                barrier.wait().await;
                Ok(HelperResponse::ok())
            }
        });
        let h3 = create_handler(move |_| {
            let barrier = Arc::clone(&h3_barrier);
            async move {
                barrier.wait().await;
                Ok(HelperResponse::ok())
            }
        });
        args.mpc_handlers = [None, Some(h2), Some(h3)];
        let t = TestComponents::new(args);
        let qc_future = t.processor.new_query(
            t.first_transport,
            t.shard_transport.clone_ref(),
            t.query_config,
        );
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let _qc = poll_immediate(&mut qc_future).await;

        assert_eq!(
            QueryStatus::Preparing,
            t.processor
                .query_status(t.shard_transport.clone_ref(), QueryId)
                .await
                .unwrap()
        );
        // unblock sends
        barrier.wait().await;

        let qc = qc_future.await.unwrap();
        let expected_assignment = RoleAssignment::new(HelperIdentity::make_three());

        assert_eq!(
            PrepareQuery {
                query_id: QueryId,
                config: t.query_config,
                roles: expected_assignment,
            },
            qc
        );
        assert_eq!(
            QueryStatus::AwaitingInputs,
            t.processor
                .query_status(t.shard_transport.clone_ref(), QueryId)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let t = TestComponents::new(TestComponentsArgs::default());
        let st = t.shard_transport;
        let _ = t
            .processor
            .new_query(
                Transport::clone_ref(&t.first_transport),
                Transport::clone_ref(&st),
                t.query_config,
            )
            .await
            .unwrap();
        assert!(matches!(
            t.processor
                .new_query(t.first_transport, st, t.query_config)
                .await,
            Err(NewQueryError::State(StateError::AlreadyRunning)),
        ));
    }

    #[tokio::test]
    async fn prepare_error() {
        let mut args = TestComponentsArgs::default();
        let h2 = helper_respond_ok();
        let h3 = create_handler(|_| async move {
            Err(ApiError::QueryPrepare(PrepareQueryError::WrongTarget))
        });
        args.mpc_handlers = [None, Some(h2), Some(h3)];
        let t = TestComponents::new(args);
        assert!(matches!(
            t.processor
                .new_query(t.first_transport, t.shard_transport, t.query_config)
                .await
                .unwrap_err(),
            NewQueryError::MpcTransport(_)
        ));
    }

    /// Context:
    /// * From the standpoint of the leader shard in Helper 1
    /// * When receiving a new query
    ///
    /// This test makes sure that if there's an error in shard 2, in this case a query is (still)
    /// being run, that error gets reported back.
    #[tokio::test]
    async fn shard_prepare_error() {
        fn shard_handle(si: ShardIndex) -> Arc<dyn RequestHandler<ShardIndex>> {
            create_handler(move |_| async move {
                if si == ShardIndex::from(2) {
                    Err(ApiError::QueryPrepare(PrepareQueryError::AlreadyRunning))
                } else {
                    Ok(HelperResponse::ok())
                }
            })
        }
        let mut args = TestComponentsArgs {
            shard_count: 4,
            ..Default::default()
        };
        args.set_shard_handler(shard_handle);
        let t = TestComponents::new(args);
        let r = t
            .processor
            .new_query(
                t.first_transport,
                t.shard_transport.clone_ref(),
                t.query_config,
            )
            .await;
        // The following makes sure the error is a broadcast error from shard 2
        assert!(r.is_err());
        if let Err(e) = r {
            if let NewQueryError::ShardBroadcastError(be) = e {
                assert_eq!(be.failures[0].0, ShardIndex::from(2));
            } else {
                panic!("Unexpected error type");
            }
        }
        assert!(matches!(
            t.processor
                .query_status(t.shard_transport, QueryId)
                .await
                .unwrap_err(),
            QueryStatusError::NoSuchQuery(_)
        ));
    }

    /// Context:
    /// * From the standpoint of the leader shard in Helper 1
    /// * When receiving a new query
    ///
    /// This test makes sure that if there's an error reported from other helpers, the state is set
    /// back to ready to accept queries.
    #[tokio::test]
    async fn new_query_can_recover_from_prepare_helper_error() {
        // First we setup MPC handlers that will return some error
        let mut args = TestComponentsArgs::default();
        let h2 = helper_respond_ok();
        let h3 = create_handler(|_| async move {
            Err(ApiError::QueryPrepare(PrepareQueryError::WrongTarget))
        });
        args.mpc_handlers = [None, Some(h2), Some(h3)];
        let t = TestComponents::new(args);

        // We should see that error surface on new_query
        assert!(matches!(
            t.processor
                .new_query(
                    t.first_transport.clone_ref(),
                    t.shard_transport.clone_ref(),
                    t.query_config
                )
                .await
                .unwrap_err(),
            NewQueryError::MpcTransport(_)
        ));

        // We check the internal state of the processor
        assert!(t.processor.get_status(QueryId).is_none());
    }

    mod complete {

        use crate::{
            helpers::{make_owned_handler, routing::RouteId, Transport},
            query::{
                processor::{
                    tests::{HelperResponse, TestComponents, TestComponentsArgs},
                    QueryId,
                },
                ProtocolResult, QueryCompletionError,
            },
            sharding::ShardIndex,
        };

        #[tokio::test]
        async fn complete_basic() {
            let t = TestComponents::default();
            let query_id = t.new_running_query().await;

            assert_eq!(
                TestComponents::COMPLETE_QUERY_RESULT.to_bytes(),
                t.processor
                    .complete(query_id, t.shard_transport.clone_ref())
                    .await
                    .unwrap()
                    .to_bytes()
            );
        }

        #[tokio::test]
        #[should_panic(expected = "QueryCompletion(NoSuchQuery(QueryId))")]
        async fn complete_one_shard_fails() {
            let mut args = TestComponentsArgs::default();

            args.set_shard_handler(|shard_id| {
                make_owned_handler(move |req, _| {
                    if shard_id != ShardIndex::from(1) || req.route != RouteId::CompleteQuery {
                        futures::future::ok(HelperResponse::ok())
                    } else {
                        futures::future::err(QueryCompletionError::NoSuchQuery(QueryId).into())
                    }
                })
            });

            let t = TestComponents::new(args);
            let query_id = t.new_running_query().await;

            let _ = t
                .processor
                .complete(query_id, t.shard_transport.clone_ref())
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn only_leader_broadcasts() {
            let mut args = TestComponentsArgs::default();

            args.set_shard_handler(|shard_id| {
                make_owned_handler(move |_req, _| {
                    if shard_id == ShardIndex::FIRST {
                        panic!("Leader shard must not receive requests through shard channels");
                    } else {
                        futures::future::ok(HelperResponse::ok())
                    }
                })
            });

            let t = TestComponents::new(args);
            let query_id = t.new_running_query().await;

            t.processor
                .complete(query_id, t.shard_transport.clone_ref())
                .await
                .unwrap();
        }
    }

    mod prepare {
        use super::*;
        use crate::query::QueryStatusError;

        #[tokio::test]
        async fn happy_case() {
            let req = prepare_query();
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .query_status(t.shard_transport.clone_ref(), QueryId)
                    .await
                    .unwrap_err(),
                QueryStatusError::NoSuchQuery(_)
            ));
            t.processor
                .prepare_helper(t.second_transport, t.shard_transport.clone_ref(), req)
                .await
                .unwrap();
            assert_eq!(
                QueryStatus::AwaitingInputs,
                t.processor
                    .query_status(t.shard_transport, QueryId)
                    .await
                    .unwrap()
            );
        }

        #[tokio::test]
        async fn rejects_if_coordinator() {
            let req = prepare_query();
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .prepare_helper(t.first_transport, t.shard_transport, req)
                    .await,
                Err(PrepareQueryError::WrongTarget)
            ));
        }

        /// Context:
        /// * From the standpoint of the second shard in Helper 2
        ///
        /// This test makes sure that an error is returned if I get a [`Processor::prepare_helper`]
        /// call. Only the shard leader (shard 0) should handle those calls.
        #[tokio::test]
        async fn rejects_if_not_shard_leader() {
            let req = prepare_query();
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .prepare_helper(
                        t.second_transport,
                        t.shard_network
                            .transport(HelperIdentity::TWO, ShardIndex::from(1)),
                        req
                    )
                    .await,
                Err(PrepareQueryError::NotLeader(_))
            ));
        }

        /// Context:
        /// * From the standpoint of the leader shard in Helper 2
        ///
        /// This test makes sure that an error is returned if I get a [`Processor::prepare_shard`]
        /// call. Only non-leaders (1,2,3...) should handle those calls.
        #[tokio::test]
        async fn shard_not_leader() {
            let req = prepare_query();
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .prepare_shard(
                        &t.shard_network
                            .transport(HelperIdentity::TWO, ShardIndex::FIRST),
                        req
                    )
                    .unwrap_err(),
                PrepareQueryError::Leader
            ));
        }

        /// This tests that both [`Processor::prepare_helper`] and [`Processor::prepare_shard`]
        /// return an [`PrepareQueryError::AlreadyRunning`] error if the internal processor state
        /// already has a running query.
        #[tokio::test]
        async fn rejects_if_query_exists() {
            let req = prepare_query();
            let t = TestComponents::new(TestComponentsArgs::default());
            // We set the processor to run a query so that subsequent calls fail.
            t.processor
                .prepare_helper(
                    t.second_transport.clone_ref(),
                    t.shard_transport.clone_ref(),
                    req.clone(),
                )
                .await
                .unwrap();

            // both helper and shard APIs should fail
            assert!(matches!(
                t.processor
                    .prepare_helper(
                        t.second_transport,
                        t.shard_transport.clone_ref(),
                        req.clone()
                    )
                    .await,
                Err(PrepareQueryError::AlreadyRunning)
            ));
            assert!(matches!(
                t.processor.prepare_shard(
                    &t.shard_network
                        .transport(HelperIdentity::ONE, ShardIndex::from(1)),
                    req
                ),
                Err(PrepareQueryError::AlreadyRunning)
            ));
        }
    }

    mod query_status {

        use super::*;
        use crate::{helpers::query::CompareStatusRequest, protocol::QueryId};

        /// * From the standpoint of leader shard in Helper 1
        /// * On query_status
        ///
        /// The min state should be returned. In this case, if I, as leader, am in AwaitingInputs
        /// state and shards report that they are further ahead (Completed and Running), then my
        /// state is returned.
        #[tokio::test]
        async fn combined_status_response() {
            fn shard_handle(si: ShardIndex) -> Arc<dyn RequestHandler<ShardIndex>> {
                const FOURTH_SHARD: ShardIndex = ShardIndex::from_u32(3);
                const THIRD_SHARD: ShardIndex = ShardIndex::from_u32(2);
                create_handler(move |_| async move {
                    match si {
                        FOURTH_SHARD => {
                            Err(ApiError::QueryStatus(QueryStatusError::DifferentStatus {
                                query_id: QueryId,
                                my_status: QueryStatus::Completed,
                                other_status: QueryStatus::Preparing,
                            }))
                        }
                        THIRD_SHARD => {
                            Err(ApiError::QueryStatus(QueryStatusError::DifferentStatus {
                                query_id: QueryId,
                                my_status: QueryStatus::Running,
                                other_status: QueryStatus::Preparing,
                            }))
                        }
                        _ => Ok(HelperResponse::ok()),
                    }
                })
            }
            let mut args = TestComponentsArgs {
                shard_count: 4,
                ..Default::default()
            };
            args.set_shard_handler(shard_handle);
            let t = TestComponents::new(args);
            let req = prepare_query();
            // Using prepare shard to set the inner state, but in reality we should be using prepare_helper
            // Prepare helper will use the shard_handle defined above though and will fail. The following
            // achieves the same state.
            t.processor
                .prepare_shard(
                    &t.shard_network
                        .transport(HelperIdentity::ONE, ShardIndex::from(1)),
                    req,
                )
                .unwrap();
            let r = t
                .processor
                .query_status(t.shard_transport.clone_ref(), QueryId)
                .await;
            if let Err(e) = r {
                panic!("Unexpected error {e}");
            }
            if let Ok(st) = r {
                assert_eq!(QueryStatus::AwaitingInputs, st);
            }
        }

        /// * From the standpoint of leader shard in Helper 1
        /// * On query_status
        ///
        /// If one of my shards hasn't received the query yet (NoSuchQuery) the leader should
        /// return an error despite other shards returning their status
        #[tokio::test]
        #[should_panic(
            expected = "(ShardIndex(3), Rejected { dest: ShardIndex(3), inner: QueryStatus(NoSuchQuery(QueryId)) })"
        )]
        async fn status_query_doesnt_exist() {
            fn shard_handle(si: ShardIndex) -> Arc<dyn RequestHandler<ShardIndex>> {
                create_handler(move |_| async move {
                    if si == ShardIndex::from(3) {
                        Err(ApiError::QueryStatus(QueryStatusError::NoSuchQuery(
                            QueryId,
                        )))
                    } else if si == ShardIndex::from(2) {
                        Err(ApiError::QueryStatus(QueryStatusError::DifferentStatus {
                            query_id: QueryId,
                            my_status: QueryStatus::Running,
                            other_status: QueryStatus::Preparing,
                        }))
                    } else {
                        Ok(HelperResponse::ok())
                    }
                })
            }
            let mut args = TestComponentsArgs {
                shard_count: 4,
                ..Default::default()
            };
            args.set_shard_handler(shard_handle);
            let t = TestComponents::new(args);
            let req = prepare_query();
            // Using prepare shard to set the inner state, but in reality we should be using prepare_helper
            // Prepare_helper will use the shard_handle defined above though and will fail. The following
            // achieves the same state.
            t.processor
                .prepare_shard(
                    &t.shard_network
                        .transport(HelperIdentity::ONE, ShardIndex::from(1)),
                    req,
                )
                .unwrap();
            t.processor
                .query_status(t.shard_transport.clone_ref(), QueryId)
                .await
                .unwrap();
        }

        /// Context:
        /// * From the standpoint of the second shard in Helper 2
        ///
        /// This test makes sure that an error is returned if I get a [`Processor::query_status`]
        /// call. Only the shard leader (shard 0) should handle those calls.
        #[tokio::test]
        async fn rejects_if_not_shard_leader() {
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .query_status(
                        t.shard_network
                            .transport(HelperIdentity::TWO, ShardIndex::from(1)),
                        QueryId
                    )
                    .await,
                Err(QueryStatusError::NotLeader(_))
            ));
        }

        /// Context:
        /// * From the standpoint of the leader shard in Helper 2
        ///
        /// This test makes sure that an error is returned if I get a [`Processor::shard_status`]
        /// call. Only non-leaders (1,2,3...) should handle those calls.
        #[tokio::test]
        async fn shard_not_leader() {
            let req = CompareStatusRequest {
                query_id: QueryId,
                status: QueryStatus::Running,
            };
            let t = TestComponents::new(TestComponentsArgs::default());
            assert!(matches!(
                t.processor
                    .shard_status(
                        &t.shard_network
                            .transport(HelperIdentity::TWO, ShardIndex::FIRST),
                        &req
                    )
                    .unwrap_err(),
                QueryStatusError::Leader
            ));
        }
    }

    mod kill {
        use std::sync::Arc;

        use super::{TestComponents, TestComponentsArgs};
        use crate::{
            executor::IpaRuntime,
            helpers::Transport,
            protocol::QueryId,
            query::{
                processor::Processor,
                state::{QueryState, RunningQuery},
                QueryKillStatus,
            },
            test_executor::run,
        };

        #[test]
        fn non_existent_query() {
            run(|| async {
                let t = TestComponents::new(TestComponentsArgs::default());
                assert!(matches!(
                    t.processor.kill(QueryId),
                    Err(QueryKillStatus::NoSuchQuery(QueryId))
                ));
            });
        }

        #[test]
        fn existing_query() {
            run(|| async move {
                let mut args = TestComponentsArgs::default();
                args.mpc_handlers[0].take();
                let t = TestComponents::new(args);
                t.processor
                    .new_query(
                        t.first_transport.clone_ref(),
                        t.shard_transport.clone_ref(),
                        t.query_config,
                    )
                    .await
                    .unwrap();

                t.processor.kill(QueryId).unwrap();

                // start query again - it should work because the query was killed
                t.processor
                    .new_query(t.first_transport, t.shard_transport, t.query_config)
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

            assert_eq!(vec![Fp31::truncate_from(20u128)], results.reconstruct());

            Ok(())
        }

        #[tokio::test]
        async fn complete_query_status_poll() -> Result<(), BoxError> {
            let app = TestApp::default();
            let a = Fp31::truncate_from(4u128);
            let b = Fp31::truncate_from(5u128);
            let query_id = app
                .start_query(vec![a, b].into_iter(), test_multiply_config())
                .await?;

            while !(app.query_status(query_id).await? == QueryStatus::Completed) {
                sleep(Duration::from_millis(1)).await;
            }

            let results = app.complete_query(query_id).await?.map(|bytes| {
                semi_honest::AdditiveShare::<Fp31>::from_byte_slice_unchecked(&bytes)
                    .collect::<Vec<_>>()
            });

            assert_eq!(
                &[Fp31::truncate_from(20u128)] as &[_],
                results.reconstruct()
            );

            Ok(())
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
