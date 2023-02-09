use crate::{
    ff::FieldType,
    helpers::{transport::ByteArrStream, RoleAssignment, TransportCommand},
    protocol::{QueryId, Substep},
    query::ProtocolResult,
};
use std::fmt::{Debug, Formatter};
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
    pub input_stream: ByteArrStream,
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "query_inputs[{:?}]", self.query_id)
    }
}

pub enum QueryCommand {
    Create(QueryConfig, oneshot::Sender<QueryId>),
    Prepare(PrepareQuery, oneshot::Sender<()>),
    Input(QueryInput, oneshot::Sender<()>),
    Results(QueryId, oneshot::Sender<Box<dyn ProtocolResult>>),
}

impl Debug for QueryCommand {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "QueryCommand: {:?}", self.query_id())?;
        match self {
            QueryCommand::Create(config, _) => {
                write!(f, "[{config:?}]")
            }
            QueryCommand::Prepare(prepare, _) => {
                write!(f, "[{prepare:?}]")
            }
            QueryCommand::Input(input, _) => {
                write!(f, "[{input:?}]")
            }
            QueryCommand::Results(query_id, _) => {
                write!(f, "{query_id:?} [Results]")
            }
        }
    }
}

impl QueryCommand {
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Create(_, _) => "Query Create",
            Self::Prepare(_, _) => "Query Prepare",
            Self::Input(_, _) => "Query Input",
            Self::Results(_, _) => "Query Results",
        }
    }

    #[must_use]
    pub fn query_id(&self) -> Option<QueryId> {
        match self {
            Self::Create(_, _) => None,
            Self::Prepare(data, _) => Some(data.query_id),
            Self::Input(data, _) => Some(data.query_id),
            Self::Results(query_id, _) => Some(*query_id),
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
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestMultiply,
    IPA(IpaQueryConfig),
}

impl QueryType {
    pub const TEST_MULTIPLY_STR: &'static str = "test-multiply";
    pub const IPA_STR: &'static str = "ipa";
}

/// TODO: should this `AsRef` impl (used for `Substep`) take into account config of IPA?
impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestMultiply => Self::TEST_MULTIPLY_STR,
            QueryType::IPA(_) => Self::IPA_STR,
        }
    }
}

impl Substep for QueryType {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct IpaQueryConfig {
    pub per_user_credit_cap: u32,
    pub max_breakdown_key: u128,
    pub num_multi_bits: u32,
}

impl From<IpaQueryConfig> for QueryType {
    fn from(value: IpaQueryConfig) -> Self {
        QueryType::IPA(value)
    }
}
