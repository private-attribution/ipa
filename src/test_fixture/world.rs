use crate::{
    helpers::messaging::{Gateway, GatewayConfig},
    protocol::{prss::Endpoint as PrssEndpoint, QueryId},
    test_fixture::{fabric::InMemoryNetwork, logging, make_participants},
};
use std::{fmt::Debug, sync::Arc};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld {
    pub query_id: QueryId,
    pub gateways: [Gateway; 3],
    pub participants: [PrssEndpoint; 3],
    _network: Arc<InMemoryNetwork>,
}

#[derive(Copy, Clone)]
pub struct TestWorldConfig {
    gateway_config: GatewayConfig,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            // buffer capacity = 1 effectively means no buffering. This is the desired mode
            // for unit tests because they may not produce enough data to trigger buffer flush
            gateway_config: GatewayConfig {
                send_buffer_capacity: 1,
            },
        }
    }
}

/// Creates a new `TestWorld` instance.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn make(query_id: QueryId) -> TestWorld {
    logging::setup();

    let config = TestWorldConfig::default();
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let network = InMemoryNetwork::new();
    let gateways = network
        .endpoints
        .iter()
        .map(|endpoint| Gateway::new(endpoint.identity, endpoint, config.gateway_config))
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
