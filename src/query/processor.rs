use super::state::{QueryState, QueryStatus, RunningQueries, StateError};
use crate::helpers::messaging::Gateway;
use crate::helpers::{GatewayConfig, HelperIdentity, Role, Transport, TransportError, RoleAssignment};
use crate::protocol::QueryId;
use futures_util::future::try_join;
use crate::helpers::network::Network;
use crate::helpers::query::{CreateQuery, PrepareQuery, QueryCommand, QueryType};

#[allow(dead_code)]
pub struct Processor<T: Transport> {
    transport: T,
    identities: [HelperIdentity; 3],
    queries: RunningQueries,
}

#[allow(dead_code)]
impl<T: Transport> Processor<T> {
    pub fn new(transport: T, identities: [HelperIdentity; 3]) -> Self {
        Self {
            transport,
            identities,
            queries: RunningQueries::default(),
        }
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

#[allow(dead_code)]
impl<T: Transport + Clone> Processor<T> {
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
        req: &CreateQuery,
    ) -> Result<PrepareQuery, NewQueryError> {
        let query_id = QueryId;
        let handle = self.queries.handle(query_id);
        handle.set_state(QueryState::Preparing)?;

        // invariant: this helper's identity must be the first element in the array.
        let this = self.identities[0].clone();
        let right = self.identities[1].clone();
        let left = self.identities[2].clone();

        let roles = RoleAssignment::try_from([(this, Role::H1), (right.clone(), Role::H2), (left.clone(), Role::H3)]).unwrap();
        let network = Network::new(self.transport.clone(), query_id, roles.clone());

        let prepare_request = PrepareQuery { query_id, field_type: req.field_type, query_type: req.query_type, roles };

        try_join(
            self.transport.send(&left, QueryCommand::Prepare(prepare_request.clone())),
            self.transport.send(&right, QueryCommand::Prepare(prepare_request.clone())),
        )
            .await?;

        let gateway = Gateway::new(Role::H1, network, GatewayConfig::default()).await;

        handle.set_state(QueryState::AwaitingInputs(gateway))?;

        Ok(prepare_request)
    }

    pub fn status(&self, query_id: QueryId) -> Option<QueryStatus> {
        self.queries.get_status(query_id)
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::sync::Arc;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use super::*;
    use crate::ff::FieldType;
    use crate::test_fixture::transport::{DelayedTransport, FailingTransport, InMemoryNetwork};

    #[tokio::test]
    async fn new_query() {
        let network = InMemoryNetwork::default();
        let transport = DelayedTransport::new(Arc::downgrade(&network.transports[0]), 3);

        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport.clone(), identities);
        let request = CreateQuery {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let qc_future = processor.new_query(&request);
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
                field_type: FieldType::Fp32BitPrime,
                query_type: QueryType::TestMultiply,
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
        let processor = Processor::new(transport, identities);
        let request = CreateQuery {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        let _qc = processor.new_query(&request).await.unwrap();
        assert!(matches!(
            processor.new_query(&request).await,
            Err(NewQueryError::StateError {
                source: StateError::AlreadyRunning
            })
        ));
    }

    #[tokio::test]
    async fn prepare_rejected() {
        let transport =
            FailingTransport::new(|command| TransportError::SendFailed {
                inner: "Transport failed".into(),
                command,
            });
        let identities = HelperIdentity::make_three();
        let processor = Processor::new(transport, identities);
        let request = CreateQuery {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::TestMultiply,
        };

        assert!(matches!(
            processor.new_query(&request).await,
            Err(NewQueryError::TransportError {
                source: TransportError::SendFailed { .. }
            })
        ));
    }
}
