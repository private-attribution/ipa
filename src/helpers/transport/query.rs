use crate::{
    ff::FieldType,
    helpers::{
        transport::{ByteArrStream, NoQueryId, NoStep},
        RoleAssignment, RouteId, RouteParams,
    },
    protocol::{QueryId, Substep},
    query::ProtocolResult,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use tokio::sync::oneshot;

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct QueryConfig {
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Clone, Debug)]
#[cfg_attr(test, derive(PartialEq))]
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

impl RouteParams<RouteId, NoQueryId, NoStep> for &QueryConfig {
    type Params = String;

    fn resource_identifier(&self) -> RouteId {
        RouteId::ReceiveQuery
    }

    fn query_id(&self) -> NoQueryId {
        NoQueryId
    }

    fn step(&self) -> NoStep {
        NoStep
    }

    #[cfg(feature = "enable-serde")]
    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
    }

    #[cfg(not(feature = "enable-serde"))]
    fn extra(&self) -> Self::Params {
        unimplemented!()
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

#[derive(Clone, Debug, PartialEq)]
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DifferentialPrivacy {
    epsilon: f64,
    delta: f64,
}

impl DifferentialPrivacy {
    #[must_use]
    pub fn new(epsilon: f64, delta: f64) -> Self {
        Self { epsilon, delta }
    }
}

#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "enable-serde", derive(Serialize, Deserialize))]
pub struct IpaQueryConfig {
    pub per_user_credit_cap: u32,
    pub max_breakdown_key: u32,
    pub attribution_window_seconds: u32,
    pub num_multi_bits: u32,
    pub dp: Option<DifferentialPrivacy>,
}

impl Default for IpaQueryConfig {
    fn default() -> Self {
        Self {
            per_user_credit_cap: 3,
            max_breakdown_key: 64,
            attribution_window_seconds: 0,
            num_multi_bits: 3,
            dp: None,
        }
    }
}

impl IpaQueryConfig {
    #[must_use]
    pub fn new(
        per_user_credit_cap: u32,
        max_breakdown_key: u32,
        attribution_window_seconds: u32,
        num_multi_bits: u32,
        dp: Option<DifferentialPrivacy>,
    ) -> Self {
        Self {
            per_user_credit_cap,
            max_breakdown_key,
            attribution_window_seconds,
            num_multi_bits,
            dp,
        }
    }
}

impl From<IpaQueryConfig> for QueryType {
    fn from(value: IpaQueryConfig) -> Self {
        QueryType::Ipa(value)
    }
}
