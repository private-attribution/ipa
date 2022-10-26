use crate::helpers::messaging::GatewayConfig;
use crate::{
    helpers::messaging::Gateway,
    protocol::{prss::Endpoint as PrssEndpoint, QueryId},
    test_fixture::{fabric::InMemoryNetwork, make_participants},
};
use std::time::Duration;
use std::{fmt::Debug, sync::Arc};
use crate::helpers::buffers::SendBufferConfig;

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

#[derive(Copy, Clone)]
pub struct TestWorldConfig {
    gateway_config: GatewayConfig,
}

impl Default for TestWorldConfig {
    fn default() -> Self {
        Self {
            gateway_config: GatewayConfig {
                // flush threshold = 1 effectively means no buffering. This is the desired mode
                // for unit tests because they may not produce enough data to trigger buffer flush
                send_buffer_config: SendBufferConfig::new(1.try_into().unwrap(), 1.try_into().unwrap()),
            },
        }
    }
}

impl TestWorldConfig {
    #[must_use]
    pub fn new(gateway_config: GatewayConfig) -> Self {
        Self { gateway_config }
    }
}

/// Creates a new `TestWorld` instance using the provided `config`.
#[must_use]
#[allow(clippy::missing_panics_doc)]
pub fn make_with_config(query_id: QueryId, config: TestWorldConfig) -> TestWorld {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let network = InMemoryNetwork::new();
    let gateways = network
        .endpoints
        .iter()
        .map(|endpoint| {
            Gateway::new(
                endpoint.identity,
                Arc::clone(endpoint),
                config.gateway_config,
            )
        })
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

/// Creates a new `TestWorld` instance.
#[must_use]
pub fn make(query_id: QueryId) -> TestWorld {
    make_with_config(query_id, TestWorldConfig::default())
}
