use crate::helpers::messaging::Gateway;
use crate::helpers::prss::{Participant, SpaceIndex};
use crate::protocol::{QueryId, Step};
use crate::test_fixture::make_participants;
use std::fmt::{Debug, Formatter};
use std::sync::Arc;
use rand::rngs::StdRng;
use rand::thread_rng;
use rand_core::SeedableRng;
use crate::test_fixture::fabric::{InMemoryEndpoint, InMemoryNetwork};

/// Test environment for protocols to run tests that require communication between helpers.
/// For now the messages sent through it never leave the test infra memory perimeter, so
/// there is no need to associate each of them with `QueryId`, but this API makes it possible
/// to do if we need it.
#[derive(Debug)]
#[allow(clippy::module_name_repetitions)]
pub struct TestWorld<'a, S: SpaceIndex> {
    pub query_id: QueryId,
    pub gateways: [Gateway<'a, S, InMemoryEndpoint<S>>; 3],
    pub participants: [Participant<S>; 3],
    network: &'a InMemoryNetwork<S>,
}

#[must_use]
pub fn make<'a, S: Step + SpaceIndex>(query_id: QueryId) -> TestWorld<'a, S> {
    let participants = make_participants();
    let participants = [participants.0, participants.1, participants.2];
    let rng = StdRng::from_entropy();
    let network: &'static InMemoryNetwork<S> = Box::leak(Box::new(InMemoryNetwork::new(rng)));
    let gateways = network.endpoints.iter().map(|fabric| {
        Gateway::new(fabric.id, fabric)
    }).collect::<Vec<_>>().try_into().unwrap();

    TestWorld {
        query_id,
        gateways,
        participants,
        network
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Hash)]
pub enum TestStep {
    Mul1(u8),
    Mul2,
}

impl Debug for TestStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            TestStep::Mul1(v) => write!(f, "TestStep/Mul1[{}]", v),
            TestStep::Mul2 => write!(f, "TestStep/Mul2"),
        }
    }
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
