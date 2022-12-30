use crate::helpers::TransportError;
use crate::{
    helpers::{
        messaging::Gateway,
        network::Network,
        query::{PrepareQuery, QueryCommand, QueryConfig, QueryInput},
        GatewayConfig, HelperIdentity, Role, RoleAssignment, SubscriptionType, Transport,
        TransportCommand,
    },
    protocol::QueryId,
    query::{
        executor,
        state::{QueryState, QueryStatus, RunningQueries, StateError},
        ProtocolResult,
    },
};
use futures::StreamExt;
use futures_util::future::try_join;
use pin_project::pin_project;
use std::collections::hash_map::Entry;
use std::fmt::{Debug, Formatter};
use tokio::sync::oneshot;

#[allow(dead_code)]
#[pin_project]
pub struct Processor<T: Transport> {
    /// Input stream of commands this processor is attached to. It is not being actively listened
    /// by this instance. Instead, commands are being consumed on demand when an external entity
    /// drives it by calling [`handle_next`] function.
    #[pin]
    command_stream: T::CommandStream,
    transport: T,
    identities: [HelperIdentity; 3],
    queries: RunningQueries,
}

impl<T: Transport> Debug for Processor<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "query_processor")
    }
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

#[allow(dead_code)]
impl<T: Transport + Clone> Processor<T> {
    pub async fn new(transport: T, identities: [HelperIdentity; 3]) -> Self {
        Self {
            command_stream: transport.subscribe(SubscriptionType::QueryManagement).await,
            transport,
            identities,
            queries: RunningQueries::default(),
        }
    }

    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka coordinator).
    /// and is free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers).
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    pub async fn new_query(&self, req: QueryConfig) -> Result<PrepareQuery, NewQueryError> {
        let query_id = QueryId;
        let handle = self.queries.handle(query_id);
        handle.set_state(QueryState::Preparing(req))?;

        // invariant: this helper's identity must be the first element in the array.
        let this = self.identities[0].clone();
        let right = self.identities[1].clone();
        let left = self.identities[2].clone();

        let roles = RoleAssignment::try_from([
            (this, Role::H1),
            (right.clone(), Role::H2),
            (left.clone(), Role::H3),
        ])
        .unwrap();

        let network = Network::new(self.transport.clone(), query_id, roles.clone());

        let prepare_request = PrepareQuery {
            query_id,
            config: req,
            roles,
        };

        let (left_tx, left_rx) = oneshot::channel();
        let (right_tx, right_rx) = oneshot::channel();
        try_join(
            self.transport.send(
                &left,
                QueryCommand::Prepare(prepare_request.clone(), left_tx),
            ),
            self.transport.send(
                &right,
                QueryCommand::Prepare(prepare_request.clone(), right_tx),
            ),
        )
        .await?;
        // await responses from prepare commands
        try_join(left_rx, right_rx).await?;

        let gateway = Gateway::new(Role::H1, network, GatewayConfig::default()).await;

        handle.set_state(QueryState::AwaitingInputs(req, gateway))?;

        Ok(prepare_request)
    }

    /// On prepare, each follower:
    /// * ensures that it is not the leader on this query
    /// * query is not registered yet
    /// * creates gateway and network
    /// * registers query
    pub async fn prepare(&self, req: PrepareQuery) -> Result<(), PrepareQueryError> {
        let my_role = req.roles.role(&self.transport.identity());

        if my_role == Role::H1 {
            return Err(PrepareQueryError::WrongTarget);
        }
        let handle = self.queries.handle(req.query_id);
        if handle.status().is_some() {
            return Err(PrepareQueryError::AlreadyRunning);
        }

        let network = Network::new(self.transport.clone(), req.query_id, req.roles.clone());
        let gateway = Gateway::new(my_role, network, GatewayConfig::default()).await;

        handle.set_state(QueryState::AwaitingInputs(req.config, gateway))?;

        Ok(())
    }

    /// Receive inputs for the specified query. That triggers query processing
    pub fn receive_inputs(&self, input: QueryInput) -> Result<(), QueryInputError> {
        let mut queries = self.queries.inner.lock().unwrap();
        match queries.entry(input.query_id) {
            Entry::Occupied(entry) => {
                let state = entry.remove();
                if let QueryState::AwaitingInputs(config, gateway) = state {
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

    /// Handle the next command from the input stream.
    ///
    /// ## Panics
    /// if command is not a query command or if the command stream is closed
    pub async fn handle_next(&mut self) {
        if let Some(command) = self.command_stream.next().await {
            tracing::trace!("new command: {:?}", command);
            match command.payload {
                TransportCommand::Query(QueryCommand::Create(req, resp)) => {
                    let result = self.new_query(req).await.unwrap();
                    resp.send(result.query_id).unwrap();
                }
                TransportCommand::Query(QueryCommand::Prepare(req, resp)) => {
                    self.prepare(req).await.unwrap();
                    resp.send(()).unwrap();
                }
                TransportCommand::Query(QueryCommand::Input(query_input, resp)) => {
                    self.receive_inputs(query_input).unwrap();
                    resp.send(()).unwrap();
                }
                TransportCommand::StepData { .. } => panic!("unexpected command: {command:?}"),
            }
        }
    }

    /// Awaits the query completion
    pub async fn complete(
        &mut self,
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
    use crate::ff::FieldType;
    use crate::helpers::query::QueryType;
    use crate::helpers::TransportError;
    use crate::test_fixture::transport::{DelayedTransport, FailingTransport, InMemoryNetwork};
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use std::sync::Arc;

    /// set up 3 query processors in active-passive mode. The first processor is returned and can be
    /// used to drive query workflow, while two others will be spawned in a tokio task and will
    /// be listening for incoming commands.
    async fn active_passive<T: Transport + Clone>(transports: [T; 3]) -> Processor<T> {
        let identities = HelperIdentity::make_three();
        let [t0, t1, t2] = transports;
        tokio::spawn({
            let identities = identities.clone();
            async move {
                let mut processor2 = Processor::new(t1, identities.clone()).await;
                let mut processor3 = Processor::new(t2, identities).await;
                // don't use tokio::select! here because it cancels one of the futures if another one is making progress
                // that causes events to be dropped
                loop {
                    processor2.handle_next().await;
                    processor3.handle_next().await;
                }
            }
        });

        Processor::new(t0, identities).await
    }

    #[tokio::test]
    async fn new_query() {
        let network = InMemoryNetwork::default();
        let [t0, t1, t2] = network.transports().map(|t| DelayedTransport::new(t, 3));
        let processor = active_passive([t0.clone(), t1, t2]).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let qc_future = processor.new_query(request);
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let _qc = poll_immediate(&mut qc_future).await;

        assert_eq!(Some(QueryStatus::Preparing), processor.status(QueryId));
        t0.wait().await;

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
        assert_eq!(Some(QueryStatus::AwaitingInputs), processor.status(QueryId));
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let network = InMemoryNetwork::default();
        let processor = active_passive(network.transports()).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let _qc = processor.new_query(request).await.unwrap();
        assert!(matches!(
            processor.new_query(request).await,
            Err(NewQueryError::State(StateError::AlreadyRunning)),
        ));
    }

    #[tokio::test]
    async fn prepare_rejected() {
        let network = InMemoryNetwork::default();
        let transport = Arc::downgrade(&network.transports[0]);
        let transport = FailingTransport::new(transport, |command| TransportError::SendFailed {
            command_name: Some(command.name()),
            query_id: command.query_id(),
            inner: "Transport failed".into(),
        });
        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport, identities).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        assert!(matches!(
            processor.new_query(request).await,
            Err(NewQueryError::Transport(TransportError::SendFailed { .. }))
        ));
    }

    mod prepare {
        use super::*;

        fn prepare_query(identities: &[HelperIdentity; 3]) -> PrepareQuery {
            PrepareQuery {
                query_id: QueryId,
                config: QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                },
                roles: RoleAssignment::new(identities.clone()),
            }
        }

        #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
        async fn happy_case() {
            let network = InMemoryNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(&identities);
            let transport = network.transport(&identities[1]).unwrap();

            let processor = Processor::new(transport, identities).await;

            assert_eq!(None, processor.status(QueryId));
            processor.prepare(req).await.unwrap();
            assert_eq!(Some(QueryStatus::AwaitingInputs), processor.status(QueryId));
        }

        #[tokio::test]
        async fn rejects_if_coordinator() {
            let network = InMemoryNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(&identities);
            let transport = network.transport(&identities[0]).unwrap();
            let processor = Processor::new(transport, identities).await;

            assert!(matches!(
                processor.prepare(req).await,
                Err(PrepareQueryError::WrongTarget)
            ));
        }

        #[tokio::test]
        async fn rejects_if_query_exists() {
            let network = InMemoryNetwork::default();
            let identities = HelperIdentity::make_three();
            let req = prepare_query(&identities);
            let transport = network.transport(&identities[1]).unwrap();

            let processor = Processor::new(transport, identities).await;
            processor.prepare(req.clone()).await.unwrap();
            assert!(matches!(
                processor.prepare(req).await,
                Err(PrepareQueryError::AlreadyRunning)
            ));
        }
    }

    mod e2e {
        use super::*;
        use crate::ff::Fp31;
        use crate::helpers::query::{IPAQueryConfig, QueryInput};
        use crate::protocol::attribution::AggregateCreditOutputRow;
        use crate::protocol::ipa::test_cases::Simple;
        use crate::protocol::ipa::IPAInputRow;
        use crate::secret_sharing::{IntoShares, Replicated};
        use crate::sync::Weak;
        use crate::test_fixture::transport::InMemoryTransport;
        use crate::test_fixture::Reconstruct;
        use futures_util::future::{join_all, try_join_all};
        use futures_util::stream;
        use tokio::sync::oneshot;

        async fn make_three(network: &InMemoryNetwork) -> [Processor<Weak<InMemoryTransport>>; 3] {
            let identities = HelperIdentity::make_three();
            join_all(network.transports.iter().map(|transport| async {
                Processor::new(Arc::downgrade(transport), identities.clone()).await
            }))
            .await
            .try_into()
            .unwrap()
        }

        async fn start_query(
            network: &InMemoryNetwork,
            config: QueryConfig,
        ) -> (QueryId, [Processor<Weak<InMemoryTransport>>; 3]) {
            // Helper 1 initiates the query, 2 and 3 must confirm
            let (tx, rx) = oneshot::channel();
            let mut processors = make_three(network).await;
            network.transports[0]
                .deliver(QueryCommand::Create(config, tx))
                .await;

            join_all(processors.iter_mut().map(Processor::handle_next)).await;

            let query_id = rx.await.unwrap();

            (query_id, processors)
        }

        #[tokio::test]
        async fn test_multiply() {
            const SZ: usize = Replicated::<Fp31>::SIZE_IN_BYTES;
            let network = InMemoryNetwork::default();
            let (query_id, mut processors) = start_query(
                &network,
                QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                },
            )
            .await;
            let a = Fp31::from(4u128);
            let b = Fp31::from(5u128);

            let helper_shares = (a, b).share().map(|(a, b)| {
                let mut slice = [0u8; 2 * SZ];
                a.serialize(&mut slice).unwrap();
                b.serialize(&mut slice[SZ..]).unwrap();
                let oks = std::iter::once(slice.to_vec()).map(Ok);
                Box::pin(stream::iter(oks))
            });

            // at this point, all helpers must be awaiting inputs
            let mut handle_resps = Vec::with_capacity(helper_shares.len());
            for (i, input) in helper_shares.into_iter().enumerate() {
                let (tx, rx) = oneshot::channel();
                network.transports[i]
                    .deliver(QueryCommand::Input(
                        QueryInput {
                            query_id,
                            field_type: FieldType::Fp31,
                            input_stream: input,
                        },
                        tx,
                    ))
                    .await;
                handle_resps.push(rx);
            }

            // process inputs and start query processing
            let mut handles = Vec::with_capacity(processors.len());
            for processor in &mut processors {
                handles.push(processor.handle_next());
            }
            join_all(handles).await;
            try_join_all(handle_resps).await.unwrap();

            let result: [_; 3] = join_all(processors.map(|mut processor| async move {
                let r = processor.complete(query_id).await.unwrap().into_bytes();
                Replicated::<Fp31>::from_byte_slice(&r).collect::<Vec<_>>()
            }))
            .await
            .try_into()
            .unwrap();

            assert_eq!(vec![Fp31::from(20u128)], result.reconstruct());
        }

        #[tokio::test]
        async fn ipa() {
            const SZ: usize = Replicated::<Fp31>::SIZE_IN_BYTES;
            type SimpleTestCase = Simple<Fp31>;
            let network = InMemoryNetwork::default();
            let (query_id, mut processors) = start_query(
                &network,
                QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: IPAQueryConfig {
                        num_bits: 20,
                        per_user_credit_cap: 3,
                        max_breakdown_key: 3,
                    }
                    .into(),
                },
            )
            .await;

            let helper_shares = SimpleTestCase::default()
                .share()
                .into_iter()
                .map(|shares| {
                    let data = shares
                        .into_iter()
                        .flat_map(|share: IPAInputRow<Fp31>| {
                            let mut buf = [0u8; IPAInputRow::<Fp31>::SIZE_IN_BYTES];
                            share.serialize(&mut buf).unwrap();

                            buf
                        })
                        .collect::<Vec<_>>();

                    Box::pin(stream::iter(std::iter::once(Ok(data))))
                })
                .collect::<Vec<_>>();

            for (i, input) in helper_shares.into_iter().enumerate() {
                let (tx, rx) = oneshot::channel();
                network.transports[i]
                    .deliver(QueryCommand::Input(
                        QueryInput {
                            query_id,
                            field_type: FieldType::Fp31,
                            input_stream: input,
                        },
                        tx,
                    ))
                    .await;
                processors[i].handle_next().await;
                rx.await.unwrap();
            }

            let result: [_; 3] = join_all(processors.map(|mut processor| async move {
                let r = processor.complete(query_id).await.unwrap().into_bytes();
                AggregateCreditOutputRow::<Fp31>::from_byte_slice(&r).collect::<Vec<_>>()
            }))
            .await
            .try_into()
            .unwrap();

            SimpleTestCase::validate(&result);
        }
    }
}
