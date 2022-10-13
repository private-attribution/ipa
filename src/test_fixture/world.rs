use crate::{
    helpers::mock::TestHelperGateway,
    protocol::{prss::Participant, QueryId},
    test_fixture::make_participants,
};
use std::fmt::Debug;

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld {
    pub query_id: QueryId,
    pub gateways: [TestHelperGateway; 3],
    pub participants: [Participant; 3],
}

#[must_use]
pub fn make(query_id: QueryId) -> TestWorld {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let gateways = TestHelperGateway::make_three();

    TestWorld {
        query_id,
        gateways,
        participants,
    }
}
