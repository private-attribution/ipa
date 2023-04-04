use std::borrow::Borrow;
use crate::{
    ff::FieldType,
    helpers::{transport::ByteArrStream, RoleAssignment},
    protocol::{QueryId, Substep},
    query::ProtocolResult,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use tokio::sync::oneshot;
use crate::helpers::{RouteId, RouteParams};
use crate::helpers::transport::NoStep;

#[derive(Copy, Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct QueryConfig {
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct PrepareQuery {
    pub query_id: QueryId,
    pub config: QueryConfig,
    pub roles: RoleAssignment,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            field_type: FieldType::Fp32BitPrime,
            #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
            query_type: QueryType::TestMultiply,
            #[cfg(not(any(test, feature = "test-fixture", feature = "cli")))]
            query_type: QueryType::Ipa(IpaQueryConfig::default()),
        }
    }
}

impl RouteParams<RouteId, QueryId, NoStep> for &PrepareQuery {
    type Params = String;

    fn resource_identifier(&self) -> RouteId {
        RouteId::PrepareQuery
    }

    fn query_id(&self) -> QueryId {
        self.query_id
    }

    fn step(&self) -> NoStep {
        NoStep
    }

    #[cfg(feature = "enable-serde")]
    fn extra(&self) -> Self::Params {
        // todo: query id will appear twice because of it. Not sure if should care about it
        // for in-memory runs though.
        serde_json::to_string(self).unwrap()
    }

    #[cfg(not(feature = "enable-serde"))]
    fn extra(&self) -> Self::Params {
        unimplemented!()
    }
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

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestMultiply,
    Ipa(IpaQueryConfig),
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
            QueryType::Ipa(_) => Self::IPA_STR,
        }
    }
}

impl Substep for QueryType {}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct IpaQueryConfig {
    pub per_user_credit_cap: u32,
    pub max_breakdown_key: u32,
    pub attribution_window_seconds: u32,
    pub num_multi_bits: u32,
}

impl Default for IpaQueryConfig {
    fn default() -> Self {
        Self {
            per_user_credit_cap: 1,
            max_breakdown_key: 64,
            attribution_window_seconds: 0,
            num_multi_bits: 3,
        }
    }
}

impl From<IpaQueryConfig> for QueryType {
    fn from(value: IpaQueryConfig) -> Self {
        QueryType::Ipa(value)
    }
}
