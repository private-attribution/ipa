use crate::error::BoxError;
use crate::helpers::messaging::Gateway;
use crate::helpers::network::Network;
use crate::helpers::{GatewayConfig, Role};
use crate::protocol::QueryId;
use async_trait::async_trait;
use futures_util::future::{join, try_join};
use hyper::Uri;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// It can't be copy and clone as it represents an internal state
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryState {
    Preparing,
    AwaitingInputs,
    Negotiating,
    Running,
    Completed,
}

impl<N: Network> From<&InternalQueryState<N>> for QueryState {
    fn from(source: &InternalQueryState<N>) -> Self {
        match source {
            InternalQueryState::Preparing => Self::Preparing,
            InternalQueryState::AwaitingInputs(_, _) => Self::AwaitingInputs,
        }
    }
}

/// TODO: a macro would be very useful here
enum InternalQueryState<N: Network> {
    Preparing,
    AwaitingInputs(N, Gateway),
}

struct Processor<'a, T: Transport> {
    transport: &'a T,
    identities: &'a [HelperIdentity; 3],
    running_queries: Arc<Mutex<HashMap<QueryId, InternalQueryState<T::AppLayer>>>>,
}

impl<'a, T: Transport> Processor<'a, T> {
    pub fn new(transport: &'a T, identities: &'a [HelperIdentity; 3]) -> Self {
        Self {
            transport,
            identities,
            running_queries: Arc::new(Mutex::new(HashMap::default())),
        }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum FieldType {
    Fp31,
    Fp32BitPrime,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum QueryType {
    #[cfg(test)]
    TestMultiply,
    IPA,
}

struct NewQueryRequest {
    field_type: FieldType,
    query_type: QueryType,
}

/// TODO: remove clone, it is a string clone and expensive
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct HelperIdentity {
    #[cfg(not(test))]
    endpoint: Uri,
    #[cfg(test)]
    id: u8,
}

impl HelperIdentity {
    #[cfg(test)]
    pub fn new(id: u8) -> Self {
        HelperIdentity { id }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RingConfiguration {
    map: HashMap<HelperIdentity, Role>,
}

impl RingConfiguration {
    pub fn prepare(assignment: [(HelperIdentity, Role); 3]) -> Self {
        Self {
            map: assignment.into()
        }
    }
}

struct RingSetup {
    map: HashMap<HelperIdentity, Role>,
}

impl RingSetup {
    pub fn assign_role(mut self, other: HelperIdentity, role: Role) -> Self {
        if let Some(prev_role) = self.map.get(&other) {
            panic!("{other:?} has been assigned a role ({prev_role:?}) already")
        }

        self.map.insert(other, role);

        self
    }

    pub fn setup(self) -> RingConfiguration {
        if self.map.len() != Role::all().len() {
            panic!(
                "Not all the roles have been assigned, ring setup is incomplete: {:?}",
                self.map
            )
        }

        RingConfiguration { map: self.map }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct QueryConfiguration {
    query_id: QueryId,
    field_type: FieldType,
    query_type: QueryType,
    ring: RingConfiguration,
}

impl QueryConfiguration {
    pub fn new(query_id: QueryId, req: &NewQueryRequest, ring: RingConfiguration) -> Self {
        Self {
            query_id,
            field_type: req.field_type.clone(),
            query_type: req.query_type.clone(),
            ring,
        }
    }
}

struct Command<'a> {
    dest: &'a HelperIdentity,
    command_type: CommandType<'a>,
}

impl <'a> Command<'a> {
    pub fn prepare(dest: &'a HelperIdentity, qc: &'a QueryConfiguration) -> Self {
        Self {
            dest,
            command_type: CommandType::Prepare(qc),
        }
    }
}

enum CommandType<'a> {
    Prepare(&'a QueryConfiguration),
}

#[derive(Debug, thiserror::Error)]
enum TransportError {
    #[error("Command has been rejected by {identity:?}")]
    CommandRejected {
        identity: HelperIdentity,
        inner: BoxError,
    },
}

#[async_trait]
trait Transport {
    type AppLayer: Network;

    async fn send(&self, command: Command<'_>) -> Result<(), TransportError>;

    fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer;
}

#[derive(thiserror::Error, Debug)]
enum NewQueryError {
    #[error("Query {0:?} is already registered and is currently in `{1:?}` state")]
    AlreadyRunning(QueryId, QueryState),
    #[error(transparent)]
    TransportError {
        #[from]
        source: TransportError,
    },
}

impl<T: Transport> Processor<'_, T> {
    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka coordinator).
    /// and is free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers).
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    async fn new_query(&self, req: &NewQueryRequest) -> Result<QueryConfiguration, NewQueryError> {
        let query_id = QueryId;
        self.register_query(query_id)?;

        // invariant: this helper's identity must be the first element in the array.
        let this = &self.identities[0];
        let left = &self.identities[1];
        let right = &self.identities[2];

        let ring = RingConfiguration::prepare([(this.clone(), Role::H1),
            (left.clone(), Role::H2),
            (right.clone(), Role::H3)
        ]);
        let network = self.transport.app_layer(&ring);
        let qc = QueryConfiguration::new(QueryId, &req, ring);

        try_join(
            self.transport.send(Command::prepare(&left, &qc)),
            self.transport.send(Command::prepare(&right, &qc)),
        )
        .await?;

        let gateway = Gateway::new(Role::H1, &network, GatewayConfig::default());

        self.running_queries.lock().unwrap().insert(
            query_id,
            InternalQueryState::AwaitingInputs(network, gateway),
        );
        Ok(qc)
    }

    pub fn status(&self, query_id: QueryId) -> Option<QueryState> {
        self.running_queries
            .lock()
            .unwrap()
            .get(&query_id)
            .map(Into::into)
    }

    fn register_query(&self, query_id: QueryId) -> Result<(), NewQueryError> {
        let mut queries = self.running_queries.lock().unwrap();
        if let Some(state) = queries.get(&query_id) {
            Err(NewQueryError::AlreadyRunning(
                query_id,
                QueryState::from(state),
            ))
        } else {
            queries.insert(query_id, InternalQueryState::Preparing);
            Ok(())
        }

    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::helpers::network::{MessageChunks, NetworkSink};
    use crate::test_fixture::network::{InMemoryEndpoint, InMemoryNetwork};
    use crate::test_fixture::TestWorld;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use std::sync::Arc;
    use tokio::sync::{Barrier, Notify};
    use tokio_stream::wrappers::ReceiverStream;
    use tracing_subscriber::filter::combinator::Not;

    struct StubTransport {
        network: Arc<InMemoryNetwork>,
    }

    #[async_trait]
    impl Transport for StubTransport {
        type AppLayer = Arc<InMemoryEndpoint>;

        async fn send(&self, command: Command<'_>) -> Result<(), TransportError> {
            Ok(())
        }

        fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
            // TODO: right now it does not matter which endpoint it returns,
            // but it will matter soon.
            Arc::clone(&self.network.endpoints[0])
        }
    }

    impl From<Arc<InMemoryNetwork>> for StubTransport {
        fn from(network: Arc<InMemoryNetwork>) -> Self {
            Self { network }
        }
    }

    /// Transport that does not acknowledge send requests until the given number of send requests
    /// is received. `wait` blocks the current task until this condition is satisfied.
    struct DelayedTransport {
        inner: StubTransport,
        barrier: Arc<Barrier>,
        send_received: Arc<Notify>,
    }

    impl DelayedTransport {
        pub fn new(inner: StubTransport, concurrent_sends: usize) -> Self {
            Self {
                inner,
                barrier: Arc::new(Barrier::new(concurrent_sends)),
                send_received: Arc::new(Notify::default()),
            }
        }

        pub async fn wait(&self) {
            self.barrier.wait().await;
        }
    }

    #[async_trait]
    impl Transport for DelayedTransport {
        type AppLayer = <StubTransport as Transport>::AppLayer;

        async fn send(&self, command: Command<'_>) -> Result<(), TransportError> {
            self.barrier.wait().await;
            self.inner.send(command).await
        }

        fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
            self.inner.app_layer(ring)
        }
    }

    /// Transport that fails every `send` request using provided `error_fn` to resolve errors.
    struct FailingTransport<F> {
        inner: StubTransport,
        error_fn: F,
    }

    impl<F: Fn(Command) -> TransportError> FailingTransport<F> {
        pub fn new(inner: StubTransport, error_fn: F) -> Self {
            Self { inner, error_fn }
        }
    }

    #[async_trait]
    impl<F: Fn(Command) -> TransportError + Sync> Transport for FailingTransport<F> {
        type AppLayer = Arc<InMemoryEndpoint>;

        async fn send(&self, command: Command<'_>) -> Result<(), TransportError> {
            Err((self.error_fn)(command))
        }

        fn app_layer(&self, ring: &RingConfiguration) -> Self::AppLayer {
            self.inner.app_layer(ring)
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn new_query() {
        let network = InMemoryNetwork::new();
        let transport = DelayedTransport::new(StubTransport::from(network), 3);

        let identities = [
            HelperIdentity::new(0),
            HelperIdentity::new(1),
            HelperIdentity::new(2),
        ];
        let processor = Processor::new(&transport, &identities);
        let request = NewQueryRequest {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let mut qc_future = processor.new_query(&request);
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        let qc = poll_immediate(&mut qc_future).await;

        assert_eq!(Some(QueryState::Preparing), processor.status(QueryId));
        transport.wait().await;

        let qc = qc_future.await.unwrap();
        let expected_assignment = RingConfiguration::prepare(
            [
                (identities[0].clone(), Role::H1),
                (identities[1].clone(), Role::H2),
                (identities[2].clone(), Role::H3),
            ]
        );

        assert_eq!(
            QueryConfiguration::new(QueryId, &request, expected_assignment),
            qc
        );
        assert_eq!(Some(QueryState::AwaitingInputs), processor.status(QueryId));
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let network = InMemoryNetwork::new();
        let transport = StubTransport::from(network);

        let identities = [
            HelperIdentity::new(0),
            HelperIdentity::new(1),
            HelperIdentity::new(2),
        ];
        let processor = Processor::new(&transport, &identities);
        let request = NewQueryRequest {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let qc = processor.new_query(&request).await.unwrap();
        assert!(matches!(
            processor.new_query(&request).await,
            Err(NewQueryError::AlreadyRunning(..))
        ));
    }

    #[tokio::test]
    async fn helpers_reject_prepare() {
        let network = InMemoryNetwork::new();
        let transport = StubTransport::from(network);
        let transport = FailingTransport::new(transport, |command| TransportError::CommandRejected {
            identity: command.dest.clone(),
            inner: "Transport failed".into(),
        });
        let identities = [
            HelperIdentity::new(0),
            HelperIdentity::new(1),
            HelperIdentity::new(2),
        ];
        let processor = Processor::new(&transport, &identities);
        let request = NewQueryRequest {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        assert!(matches!(
            processor.new_query(&request).await,
            Err(NewQueryError::TransportError {
                source: TransportError::CommandRejected { .. }
            })
        ))
    }
}
