use std::collections::hash_map::Entry;
use std::fmt::{Debug, Formatter};
use super::state::{QueryState, QueryStatus, RunningQueries, StateError};
use crate::helpers::messaging::Gateway;
use crate::helpers::network::Network;
use crate::helpers::query::{QueryConfig, PrepareQuery, QueryCommand, QueryInput};
use crate::helpers::{GatewayConfig, HelperIdentity, Role, RoleAssignment, SubscriptionType, Transport, TransportCommand, TransportError};
use crate::protocol::QueryId;
use futures_util::future::try_join;
use pin_project::pin_project;
use tokio::sync::mpsc;
use crate::task::JoinHandle;
use futures::StreamExt;
// use crate::query::query_executor;

#[allow(dead_code)]
#[pin_project]
pub struct Processor<T: Transport> {
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
    StateError {
        #[from]
        source: StateError,
    },
    #[error(transparent)]
    TransportError {
        #[from]
        source: TransportError,
    },
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
        handle.set_state(QueryState::Preparing(req.clone()))?;

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
            config: req.clone(),
            roles,
        };

        try_join(
            self.transport
                .send(&left, QueryCommand::Prepare(prepare_request.clone())),
            self.transport
                .send(&right, QueryCommand::Prepare(prepare_request.clone())),
        )
            .await?;

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

    pub async fn inputs(&self, input: &QueryInput) -> Result<(), QueryInputError> {
        match self.queries.inner.lock().unwrap().entry(input.query_id) {
            Entry::Occupied(mut entry) => {
                let state = entry.get();
                match state {
                    QueryState::AwaitingInputs(config, gateway) => {
                        Ok(())
                        // let task = tokio::spawn(query_executor(gateway, input));
                        // entry.insert(QueryState::Running(task));
                        // Ok(())
                    }
                    _ => panic!("Received request to process inputs for a query with status {:?}", QueryStatus::from(state)),
                }
            }
            // TODO: return error
            Entry::Vacant(_) => panic!("No query with id {:?}", input.query_id)
        }
    }

    pub fn status(&self, query_id: QueryId) -> Option<QueryStatus> {
        self.queries.handle(query_id).status()
    }

    pub async fn handle_next(&mut self) {
        if let Some(command) = self.command_stream.next().await {
            println!("{:?} received {:?}", self.transport.identity(), command);
            match command.payload {
                TransportCommand::Query(query_command) => {
                    match query_command {
                        QueryCommand::Create(req, resp) => {
                            let result = self.new_query(req).await.unwrap();
                            resp.send(result).unwrap()
                        }
                        QueryCommand::Prepare(req) => {
                            self.prepare(req).await.unwrap();
                        }
                        QueryCommand::Input(query_input) => {
                            panic!("not ready to handle inputs just yet")
                        }
                    }
                }
                _ => panic!("unexpected command: {command:?}")
            }
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::ff::FieldType;
    use crate::helpers::query::QueryType;
    use crate::test_fixture::transport::{DelayedTransport, FailingTransport, InMemoryNetwork};
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use std::sync::Arc;

    #[tokio::test]
    async fn new_query() {
        let network = InMemoryNetwork::default();
        let transport = DelayedTransport::new(Arc::downgrade(&network.transports[0]), 3);

        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport.clone(), identities).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let qc_future = processor.new_query(request.clone());
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let _qc = poll_immediate(&mut qc_future).await;

        assert_eq!(Some(QueryStatus::Preparing), processor.status(QueryId));
        transport.wait().await;

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
        let transport = Arc::downgrade(&network.transports[0]);

        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport, identities).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let _qc = processor.new_query(request.clone()).await.unwrap();
        assert!(matches!(
            processor.new_query(request).await,
            Err(NewQueryError::StateError {
                source: StateError::AlreadyRunning
            })
        ));
    }

    #[tokio::test]
    async fn prepare_rejected() {
        let network = InMemoryNetwork::default();
        let transport = Arc::downgrade(&network.transports[0]);
        let transport = FailingTransport::new(transport, |command| TransportError::SendFailed {
            inner: "Transport failed".into(),
            command,
        });
        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport, identities).await;
        let request = QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        assert!(matches!(
            processor.new_query(request).await,
            Err(NewQueryError::TransportError {
                source: TransportError::SendFailed { .. }
            })
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

        #[tokio::test]
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
        use std::io::Cursor;
        use futures_util::future::join_all;
        use futures_util::stream;
        use tokio::sync::oneshot;
        use crate::ff::{Field, Fp31};
        use crate::helpers::query::QueryInput;
        use crate::secret_sharing::IntoShares;
        use crate::test_fixture::transport::InMemoryTransport;
        use crate::sync::Weak;
        use super::*;

        async fn make_three(network: &InMemoryNetwork) -> [Processor<Weak<InMemoryTransport>>; 3] {
            let identities = HelperIdentity::make_three();
            join_all(network.transports.iter().map(|transport| async {
                Processor::new(Arc::downgrade(transport), identities.clone()).await
            })).await.try_into().unwrap()
        }

        #[tokio::test]
        pub async fn create_prepare() {
            let network = InMemoryNetwork::default();
            let mut processors = make_three(&network).await;

            // Helper 1 initiates the query, 2 and 3 must confirm
            let (tx, rx) = oneshot::channel();
            network.transports[0]
                .deliver(QueryCommand::Create(QueryConfig { field_type: FieldType::Fp31, query_type: QueryType::TestMultiply }, tx))
                .await;

            for mut processor in &mut processors {
                processor.handle_next().await;
            }

            let r = rx.await.unwrap();

            assert_eq!(processors[1].status(r.query_id), processors[2].status(r.query_id));
            assert_eq!(processors[2].status(r.query_id), processors[0].status(r.query_id));
            assert_eq!(Some(QueryStatus::AwaitingInputs), processors[0].status(r.query_id));
        }

        #[tokio::test]
        pub async fn create_prepare_2() {
            let network = InMemoryNetwork::default();
            let mut processors = make_three(&network).await;

            // Helper 1 initiates the query, 2 and 3 must confirm
            let (tx, rx) = oneshot::channel();
            let r = {
                network.transports[0]
                    .deliver(QueryCommand::Create(QueryConfig { field_type: FieldType::Fp31, query_type: QueryType::TestMultiply }, tx))
                    .await;

                for mut processor in &mut processors {
                    processor.handle_next().await;
                }

                rx.await.unwrap()
            };
            let a = Fp31::from(4u128);
            let b = Fp31::from(3u128);

            let helper_shares = (a, b).share()
                .map(|v| {
                    let mut slice = [0_u8; 4];
                    v.0.left().serialize(&mut slice[..1]).unwrap();
                    v.0.right().serialize(&mut slice[1..2]).unwrap();
                    v.1.left().serialize(&mut slice[2..3]).unwrap();
                    v.1.right().serialize(&mut slice[3..4]).unwrap();
                    Box::new(stream::iter(std::iter::once(slice.to_vec())))
                });

            // at this point, all helpers must be awaiting inputs
            for (i, input) in helper_shares.into_iter().enumerate() {
                network.transports[i].deliver(QueryCommand::Input(QueryInput {
                    query_id: r.query_id,
                    input_stream: input
                })).await;
            }

            // process inputs and start query processing
            for mut processor in &mut processors {
                processor.handle_next().await;
            }
            //
            // // at this point we can just spin and wait
        }
    }
}
