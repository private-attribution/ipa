use super::state::{QueryState, QueryStatus, RunningQueries, StateError};
use crate::ff::FieldType;
use crate::helpers::messaging::Gateway;
use crate::helpers::{
    TransportCommand, GatewayConfig, HelperIdentity,  Role,
    Transport, TransportError,
};
use crate::protocol::QueryId;
use futures_util::future::try_join;
use crate::helpers::query::{PrepareQuery, QueryType};

#[allow(dead_code)]
pub struct Processor<'a, T: Transport> {
    transport: &'a T,
    identities: &'a [HelperIdentity; 3],
    queries: RunningQueries<T>,
}

#[allow(dead_code)]
impl<'a, T: Transport> Processor<'a, T> {
    pub fn new(transport: &'a T, identities: &'a [HelperIdentity; 3]) -> Self {
        Self {
            transport,
            identities,
            queries: RunningQueries::default(),
        }
    }
}

#[allow(dead_code)]
pub struct NewQueryRequest {
    field_type: FieldType,
    query_type: QueryType,
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

#[allow(dead_code)]
impl<T: Transport> Processor<'_, T> {
    /// Upon receiving a new query request:
    /// * processor generates new query id
    /// * assigns roles to helpers in the ring. Helper that received new query request becomes `Role::H1` (aka coordinator).
    /// and is free to choose helpers for `Role::H2` and `Role::H3` arbitrarily (aka followers).
    /// * Requests Infra and Network layer to create resources for this query
    /// * sends `prepare` request that describes the query configuration (query id, query type, field type, roles -> endpoints or reverse) to followers and waits for the confirmation
    /// * records newly created query id internally and sets query state to awaiting data
    /// * returns query configuration
    pub async fn new_query(
        &self,
        req: &NewQueryRequest,
    ) -> Result<PrepareQuery, NewQueryError> {
        todo!()
        // let query_id = QueryId;
        // let handle = self.queries.handle(query_id);
        // handle.set_state(QueryState::Preparing)?;
        //
        // // invariant: this helper's identity must be the first element in the array.
        // let this = &self.identities[0];
        // let right = &self.identities[1];
        // let left = &self.identities[2];
        //
        // let ring = RingConfiguration::new([(this, Role::H1), (right, Role::H2), (left, Role::H3)]);
        // let network = self.transport.app_layer(&ring);
        // let qc = QueryConfiguration::new(query_id, req.field_type, req.query_type, ring);
        //
        // try_join(
        //     self.transport.send(Command::prepare(left, &qc)),
        //     self.transport.send(Command::prepare(right, &qc)),
        // )
        // .await?;
        //
        // let gateway = Gateway::new(Role::H1, &network, GatewayConfig::default());
        //
        // handle.set_state(QueryState::AwaitingInputs(network, gateway))?;
        //
        // Ok(qc)
    }

    pub fn status(&self, query_id: QueryId) -> Option<QueryStatus> {
        self.queries.get_status(query_id)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::ff::FieldType;
    //
    // use crate::helpers::{
    //     DelayedTransport, FailingTransport, QueryType, StubTransport, TransportError,
    // };
    // use crate::test_fixture::network::InMemoryNetwork;
    //
    // use futures::pin_mut;
    // use futures_util::future::poll_immediate;
    //
    // #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    // async fn new_query() {
    //     let network = InMemoryNetwork::new();
    //     let transport = DelayedTransport::new(StubTransport::from(network), 3);
    //
    //     let identities = [
    //         HelperIdentity::new(0),
    //         HelperIdentity::new(1),
    //         HelperIdentity::new(2),
    //     ];
    //     let processor = Processor::new(&transport, &identities);
    //     let request = NewQueryRequest {
    //         field_type: FieldType::Fp32BitPrime,
    //         query_type: QueryType::TestMultiply,
    //     };
    //
    //     let qc_future = processor.new_query(&request);
    //     pin_mut!(qc_future);
    //
    //     // poll future once to trigger query status change
    //     let _qc = poll_immediate(&mut qc_future).await;
    //
    //     assert_eq!(Some(QueryStatus::Preparing), processor.status(QueryId));
    //     transport.wait().await;
    //
    //     let qc = qc_future.await.unwrap();
    //     let expected_assignment = RingConfiguration::new([
    //         (&identities[0], Role::H1),
    //         (&identities[1], Role::H2),
    //         (&identities[2], Role::H3),
    //     ]);
    //
    //     assert_eq!(
    //         QueryConfiguration::new(
    //             QueryId,
    //             request.field_type,
    //             request.query_type,
    //             expected_assignment
    //         ),
    //         qc
    //     );
    //     assert_eq!(Some(QueryStatus::AwaitingInputs), processor.status(QueryId));
    // }
    //
    // #[tokio::test]
    // async fn rejects_duplicate_query_id() {
    //     let network = InMemoryNetwork::new();
    //     let transport = StubTransport::from(network);
    //
    //     let identities = [
    //         HelperIdentity::new(0),
    //         HelperIdentity::new(1),
    //         HelperIdentity::new(2),
    //     ];
    //     let processor = Processor::new(&transport, &identities);
    //     let request = NewQueryRequest {
    //         field_type: FieldType::Fp32BitPrime,
    //         query_type: QueryType::TestMultiply,
    //     };
    //
    //     let _qc = processor.new_query(&request).await.unwrap();
    //     assert!(matches!(
    //         processor.new_query(&request).await,
    //         Err(NewQueryError::StateError {
    //             source: StateError::AlreadyRunning
    //         })
    //     ));
    // }
    //
    // #[tokio::test]
    // async fn prepare_rejected() {
    //     let network = InMemoryNetwork::new();
    //     let transport = StubTransport::from(network);
    //     let transport =
    //         FailingTransport::new(transport, |command| TransportError::CommandRejected {
    //             identity: command.dest.clone(),
    //             inner: "Transport failed".into(),
    //         });
    //     let identities = [
    //         HelperIdentity::new(0),
    //         HelperIdentity::new(1),
    //         HelperIdentity::new(2),
    //     ];
    //     let processor = Processor::new(&transport, &identities);
    //     let request = NewQueryRequest {
    //         field_type: FieldType::Fp32BitPrime,
    //         query_type: QueryType::TestMultiply,
    //     };
    //
    //     assert!(matches!(
    //         processor.new_query(&request).await,
    //         Err(NewQueryError::TransportError {
    //             source: TransportError::CommandRejected { .. }
    //         })
    //     ));
    // }
}
