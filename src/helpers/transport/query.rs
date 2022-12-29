use crate::ff::FieldType;
use crate::helpers::{TransportError, RoleAssignment, TransportCommand};
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
    /// TODO: remove, we already have this information in query configuration
    pub field_type: FieldType,
    pub input_stream: Pin<Box<dyn Stream<Item = Result<Vec<u8>, TransportError>> + Send>>,
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "query_inputs[{:?}]",
            self.query_id
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
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(try_from = "&str")
)]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture"))]
    TestMultiply,
    IPA(IPAQueryConfig),
}

impl QueryType {
    const TEST_MULTIPLY_STR: &'static str = "test-multiply";
    const IPA_STR: &'static str = "ipa";
}

impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            QueryType::TestMultiply => Self::TEST_MULTIPLY_STR,
            QueryType::IPA(_) => Self::IPA_STR,
        }
    }
}

impl TryFrom<&str> for QueryType {
    type Error = TransportError;

    fn try_from(_query_type_str: &str) -> Result<Self, Self::Error> {
        unimplemented!("query type needs more arguments than just name of the protocol")
        // match query_type_str {
        //     #[cfg(any(test, feature = "test-fixture"))]
        //     Self::TEST_MULTIPLY_STR => Ok(QueryType::TestMultiply),
        //     Self::IPA_STR => Ok(QueryType::IPA),
        //     other => Err(TransportError::UnknownQueryType(other.to_string())),
        // }
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
