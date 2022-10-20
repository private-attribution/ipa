use crate::{
    helpers::messaging::Gateway,
    protocol::{prss::Endpoint as PrssEndpoint, QueryId},
    test_fixture::{fabric::InMemoryNetwork, make_participants},
};
use std::{fmt::Debug, sync::Arc};

use super::fabric::InMemoryEndpoint;

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld {
    pub query_id: QueryId,
    pub gateways: [Gateway<Arc<InMemoryEndpoint>>; 3],
    pub participants: [PrssEndpoint; 3],
    _network: Arc<InMemoryNetwork>,
}

/// Creates a new `TestWorld` instance.
///
/// # Panics
/// No panic is expected.
#[must_use]
pub fn make(query_id: QueryId) -> TestWorld {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let network = InMemoryNetwork::new();
    let gateways = network
        .endpoints
        .iter()
        .map(|endpoint| Gateway::new(endpoint.identity, Arc::clone(endpoint)))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    TestWorld {
        query_id,
        gateways,
        participants,
        _network: network,
    }
}
