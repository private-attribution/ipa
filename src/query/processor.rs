use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use async_trait::async_trait;
use futures_util::future::join;
use hyper::Uri;
use crate::helpers::messaging::Gateway;
use crate::helpers::network::Network;
use crate::helpers::{GatewayConfig, Role};
use crate::protocol::QueryId;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum QueryState {
    Preparing,
    AwaitingInputs,
    Negotiating,
    Running,
    Completed
}


struct Processor<'a, T> {
    transport: &'a T,
    identities: &'a [HelperIdentity; 3],
    running_queries: Arc<Mutex<HashMap<QueryId, QueryState>>>,
}


impl <'a, T: Transport> Processor<'a, T> {
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
    Fp32BitPrime
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum QueryType {
    #[cfg(test)]
    TestMultiply,
    IPA
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
    id: u8
}

impl HelperIdentity {
    #[cfg(test)]
    pub fn new(id: u8) -> Self {
        HelperIdentity {
            id
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RingConfiguration {
    map: HashMap<HelperIdentity, Role>,
}

impl RingConfiguration {
    pub fn prepare(current_identity: HelperIdentity) -> RingSetup {
        RingSetup {
            map: [(current_identity, Role::H1)].into()
        }
    }
}

struct RingSetup {
    map: HashMap<HelperIdentity, Role>
}

impl RingSetup {
    pub fn assign_role(&mut self, other: HelperIdentity, role: Role) {
        if let Some(prev_role) = self.map.get(&other) {
            panic!("{other:?} has been assigned a role ({prev_role:?}) already")
        }

        self.map.insert(other, role);
    }

    pub fn fin(self) -> RingConfiguration {
        if self.map.len() != Role::all().len() {
            panic!("Not all the roles have been assigned, ring setup is incomplete: {:?}", self.map)
        }

        RingConfiguration {
            map: self.map
        }
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
            ring
        }
    }
}

enum Command<'a> {
    Prepare(&'a HelperIdentity, QueryConfiguration)
}

#[async_trait]
trait Transport {
    type NetworkType: Network;
    async fn send(&self, command: Command<'_>);

    fn create_app(&self, ring: &RingConfiguration) -> Self::NetworkType;
}

#[derive(thiserror::Error, Debug)]
enum NewQueryError {
    #[error("Query {0:?} is already registered and is currently in `{1:?}` state")]
    QueryRunning(QueryId, QueryState)
}

impl <T: Transport> Processor<'_, T> {
    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka leader)
    /// and is free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers).
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    async fn new_query(&self, req: &NewQueryRequest) -> Result<QueryConfiguration, NewQueryError> {

        let query_id = QueryId;
        {
            let mut queries = self.running_queries.lock().unwrap();
            if let Some(state) = queries.get(&query_id) {
                return Err(NewQueryError::QueryRunning(query_id, *state))
            }

            queries.insert(query_id, QueryState::Preparing);
        }

        // if let Some(state) = self.running_queries.lock().unwrap().get(&query_id) {
        //     return
        // }


        // invariant: this helper's identity is always the first
        let mut ring = RingConfiguration::prepare(self.identities[0].clone());
        ring.assign_role(self.identities[1].clone(), Role::H2);
        ring.assign_role(self.identities[2].clone(), Role::H3);
        let ring = ring.fin();
        let qc = QueryConfiguration::new(QueryId, &req, ring.clone());

        let network = self.transport.create_app(&ring);
        let gateway = Gateway::new(Role::H1, &network, GatewayConfig::default());

        self.transport.send(Command::Prepare(&self.identities[1], qc.clone())).await;
        self.transport.send(Command::Prepare(&self.identities[2], qc.clone())).await;

        Ok(qc)
    }

    fn status(&self, query_id: QueryId) -> Option<QueryState> {
        self.running_queries.lock().unwrap().get(&query_id).cloned()
    }
}


#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::sync::Arc;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use super::*;
    use crate::test_fixture::network::{InMemoryEndpoint, InMemoryNetwork};
    use crate::test_fixture::TestWorld;

    struct StubTransport {
        network: Arc<InMemoryNetwork>,
    }

    #[async_trait]
    impl Transport for StubTransport {
        type NetworkType = Arc<InMemoryEndpoint>;

        async fn send(&self, command: Command<'_>) {
        }

        fn create_app(&self, ring: &RingConfiguration) -> Self::NetworkType {
            // TODO: right now it does not matter which endpoint it returns,
            // but it will matter soon. TestWorld must use another abstraction for transport layer
            Arc::clone(&self.network.endpoints[0])
        }
    }

    impl From<Arc<InMemoryNetwork>> for StubTransport {
        fn from(network: Arc<InMemoryNetwork>) -> Self {
            Self {
                network
            }
        }
    }

    #[tokio::test]
    async fn new_query() {
        // TODO: this is wrong too, test world no longer bound to query
        let network = InMemoryNetwork::new();
        let transport = StubTransport::from(network);

        let identities = [HelperIdentity::new(0), HelperIdentity::new(1), HelperIdentity::new(2)];
        let processor = Processor::new(&transport, &identities);
        let request = NewQueryRequest { field_type: FieldType::Fp32BitPrime, query_type: QueryType::TestMultiply };

        let mut qc_future = processor
            .new_query(&request);
        pin_mut!(qc_future);

        // poll future once to trigger query status change
        poll_immediate(&mut qc_future).await;


        assert_eq!(Some(QueryState::Preparing), processor.status(QueryId))

        // let mut expected_ring_conf = RingConfiguration::prepare(identities[0].clone());
        // expected_ring_conf.assign_role(identities[1].clone(), Role::H2);
        // expected_ring_conf.assign_role(identities[2].clone(), Role::H3);
        //
        //
        //
        // assert_eq!(QueryConfiguration::new(QueryId, &request, expected_ring_conf.fin()), qc);
    }

    #[tokio::test]
    async fn rejects_duplicate_query_id() {
        let network = InMemoryNetwork::new();
        let transport = StubTransport::from(network);

        let identities = [HelperIdentity::new(0), HelperIdentity::new(1), HelperIdentity::new(2)];
        let processor = Processor::new(&transport, &identities);
        let request = NewQueryRequest { field_type: FieldType::Fp32BitPrime, query_type: QueryType::TestMultiply };

        let qc = processor.new_query(&request).await.unwrap();
        assert!(
            matches!(
                processor.new_query(&request).await,
                Err(NewQueryError::QueryRunning(..))
            )
        );
    }
}