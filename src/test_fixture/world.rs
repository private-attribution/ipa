use crate::helpers::mock::TestHelperGateway;
use crate::protocol::{QueryId, Step};
use crate::prss::{Participant, SpaceIndex};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld<S: SpaceIndex> {
    pub query_id: QueryId,
    pub gateways: [TestHelperGateway<S>; 3],
    pub participants: [Participant<S>; 3],
}

#[must_use]
pub fn make<S: Step + SpaceIndex>(query_id: QueryId) -> TestWorld<S> {
    let participants = crate::prss::test::make_three();
    let participants = [participants.0, participants.1, participants.2];
    let gateways = TestHelperGateway::make_three();

    TestWorld {
        query_id,
        gateways,
        participants,
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug, Hash)]
pub enum TestStep {
    Mul1(u8),
    Mul2,
}

impl Step for TestStep {}

impl SpaceIndex for TestStep {
    const MAX: usize = 2;

    fn as_usize(&self) -> usize {
        match self {
            TestStep::Mul1(_) => 0,
            TestStep::Mul2 => 1,
        }
    }
}
