use crate::helpers::messaging::Gateway;
use crate::helpers::prss::{Participant, SpaceIndex};
use crate::protocol::{sort::ShuffleStep, QueryId, Step};
use crate::test_fixture::make_participants;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

use crate::test_fixture::fabric::{InMemoryEndpoint, InMemoryNetwork};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld<S: SpaceIndex> {
    pub query_id: QueryId,
    pub gateways: [Gateway<S, Arc<InMemoryEndpoint<S>>>; 3],
    pub participants: [Participant<S>; 3],
    _network: Arc<InMemoryNetwork<S>>,
}

/// Creates a new `TestWorld` instance.
///
/// # Panics
/// No panic is expected.
#[must_use]
pub fn make<S: Step + SpaceIndex>(query_id: QueryId) -> TestWorld<S> {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let network = InMemoryNetwork::new();
    let gateways = network
        .endpoints
        .iter()
        .map(|fabric| Gateway::new(fabric.identity, Arc::clone(fabric)))
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

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum TestStep {
    Mul1(u8),
    Mul2,
    Reshare(u8),
    Reveal(u8),
    Shuffle(ShuffleStep),
}

impl Debug for TestStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TestStep::Mul1(v) => write!(f, "TestStep/Mul1[{}]", v),
            TestStep::Mul2 => write!(f, "TestStep/Mul2"),
            TestStep::Reshare(v) => write!(f, "TestStep/Reshare[{}]", v),
            TestStep::Reveal(v) => write!(f, "TestStep/Reveal[{}]", v),
            TestStep::Shuffle(v) => write!(f, "TestStep/Shuffle[{:?}]", v),
        }
    }
}

impl Step for TestStep {}

impl SpaceIndex for TestStep {
    const MAX: usize = 5;

    fn as_usize(&self) -> usize {
        match self {
            TestStep::Mul1(_) => 0,
            TestStep::Mul2 => 1,
            TestStep::Reshare(_) => 2,
            TestStep::Reveal(_) => 3,
            TestStep::Shuffle(_) => 4,
        }
    }
}
