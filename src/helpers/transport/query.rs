use crate::ff::FieldType;
use crate::helpers::{RoleAssignment, TransportCommand};
use crate::protocol::{QueryId, Substep};
use futures::Stream;
use std::fmt::{Debug, Formatter};
use std::pin::Pin;
use tokio::sync::oneshot;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct QueryConfig {
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PrepareQuery {
    pub query_id: QueryId,
    pub config: QueryConfig,
    pub roles: RoleAssignment,
}

pub struct QueryInput {
    pub query_id: QueryId,
    pub input_stream: Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>,
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "query_inputs[{:?}]", self.query_id)
    }
}

#[derive(Debug)]
pub enum QueryCommand {
    Create(QueryConfig, oneshot::Sender<PrepareQuery>),
    Prepare(PrepareQuery),
    Input(QueryInput),
}

impl From<QueryCommand> for TransportCommand {
    fn from(value: QueryCommand) -> Self {
        TransportCommand::Query(value)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture"))]
    TestMultiply,
    IPA(IPAQueryConfig),
}

impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            QueryType::TestMultiply => "test-multiply",
            QueryType::IPA(_) => "ipa",
        }
    }
}

impl Substep for QueryType {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IPAQueryConfig {
    pub num_bits: u32,
    pub per_user_credit_cap: u32,
    pub max_breakdown_key: u128,
}

impl From<IPAQueryConfig> for QueryType {
    fn from(value: IPAQueryConfig) -> Self {
        QueryType::IPA(value)
    }
}
