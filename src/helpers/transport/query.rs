use crate::{
    ff::FieldType,
    helpers::{transport::Error, RoleAssignment, TransportCommand},
    protocol::{QueryId, Substep},
};
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
    pub field_type: FieldType,
    pub input_stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, Error>> + Send>>,
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "query_inputs[{:?}, {:?}]",
            self.query_id, self.field_type
        )
    }
}

#[derive(Debug)]
pub enum QueryCommand {
    Create(QueryConfig, oneshot::Sender<QueryId>),
    Prepare(PrepareQuery, oneshot::Sender<()>),
    Input(QueryInput, oneshot::Sender<()>),
}

impl QueryCommand {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create(_, _) => "Query Create",
            Self::Prepare(_, _) => "Query Prepare",
            Self::Input(_, _) => "Query Input",
        }
    }

    #[must_use]
    pub fn query_id(&self) -> Option<QueryId> {
        match self {
            Self::Create(_, _) => None,
            Self::Prepare(data, _) => Some(data.query_id),
            Self::Input(data, _) => Some(data.query_id),
        }
    }
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
    IPA,
}

impl QueryType {
    pub const TEST_MULTIPLY_STR: &'static str = "test-multiply";
    pub const IPA_STR: &'static str = "ipa";
}

impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            QueryType::TestMultiply => Self::TEST_MULTIPLY_STR,
            QueryType::IPA => Self::IPA_STR,
        }
    }
}

impl Substep for QueryType {}
