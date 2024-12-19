mod hybrid;

use std::{
    fmt::{Debug, Display, Formatter},
    num::NonZeroU32,
};

pub use hybrid::HybridQueryParams;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{
    ff::FieldType,
    helpers::{
        transport::{routing::RouteId, BodyStream, NoQueryId, NoStep},
        RoleAssignment, RouteParams,
    },
    protocol::QueryId,
    query::QueryStatus,
};

#[derive(Copy, Clone, Debug, Ord, PartialOrd, Eq, PartialEq, Serialize)]
pub struct QuerySize(u32);

impl QuerySize {
    pub const MAX: u32 = 1_000_000_000;
}

impl<'de> Deserialize<'de> for QuerySize {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let v = u32::deserialize(deserializer)?;
        Self::try_from(v).map_err(serde::de::Error::custom)
    }
}

impl Display for QuerySize {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, thiserror::Error)]
#[error(
    "Query size is 0 or too large. Must be within [1, {}], got: {0}",
    QuerySize::MAX
)]
pub enum BadQuerySizeError {
    U32(u32),
    USize(usize),
    I32(i32),
}

macro_rules! query_size_from_impl {
    ( $( $Int: ident => $err: expr ),+ ) => {
        $(
            impl TryFrom<$Int> for QuerySize {
                type Error = BadQuerySizeError;

                fn try_from(value: $Int) -> Result<Self, Self::Error> {
                    if value > 0 && value <= $Int::try_from(Self::MAX).expect(concat!(stringify!($Int), " is large enough to fit 1B")) {
                        Ok(Self(u32::try_from(value).unwrap()))
                    } else {
                        Err($err(value))
                    }
                }
            }
        )+
    }
}

query_size_from_impl!(u32 => BadQuerySizeError::U32, usize => BadQuerySizeError::USize, i32 => BadQuerySizeError::I32);

impl From<QuerySize> for u32 {
    fn from(value: QuerySize) -> Self {
        value.0
    }
}

impl From<QuerySize> for usize {
    fn from(value: QuerySize) -> Self {
        usize::try_from(value.0).expect("u32 fits into usize")
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct QueryConfig {
    pub size: QuerySize,
    pub field_type: FieldType,
    pub query_type: QueryType,
}

#[derive(Debug, thiserror::Error)]
pub enum QueryConfigError {
    #[error(transparent)]
    BadQuerySize(#[from] BadQuerySizeError),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct PrepareQuery {
    pub query_id: QueryId,
    pub config: QueryConfig,
    pub roles: RoleAssignment,
}

impl RouteParams<RouteId, QueryId, NoStep> for PrepareQuery {
    type Params = String;

    fn resource_identifier(&self) -> RouteId {
        RouteId::PrepareQuery
    }

    fn query_id(&self) -> QueryId {
        self.query_id
    }

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
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

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
    }
}

impl QueryConfig {
    /// Initialize new query configuration.
    ///
    /// ## Errors
    /// If query size is too large or 0.
    pub fn new<S>(
        query_type: QueryType,
        field_type: FieldType,
        size: S,
    ) -> Result<Self, QueryConfigError>
    where
        S: TryInto<QuerySize, Error = BadQuerySizeError>,
    {
        Ok(Self {
            size: size.try_into()?,
            field_type,
            query_type,
        })
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

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
    }
}

pub enum QueryInput {
    FromUrl {
        query_id: QueryId,
        url: String,
    },
    Inline {
        query_id: QueryId,
        input_stream: BodyStream,
    },
}

impl QueryInput {
    #[must_use]
    pub fn query_id(&self) -> QueryId {
        match self {
            Self::FromUrl { query_id, .. } | Self::Inline { query_id, .. } => *query_id,
        }
    }

    #[must_use]
    pub fn input_stream(self) -> Option<BodyStream> {
        match self {
            Self::Inline { input_stream, .. } => Some(input_stream),
            Self::FromUrl { .. } => None,
        }
    }

    #[must_use]
    pub fn url(&self) -> Option<&str> {
        match self {
            Self::FromUrl { url, .. } => Some(url),
            Self::Inline { .. } => None,
        }
    }
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            QueryInput::Inline {
                query_id,
                input_stream: _,
            } => f
                .debug_struct("QueryInput::Inline")
                .field("query_id", query_id)
                .finish(),
            QueryInput::FromUrl { query_id, url } => f
                .debug_struct("QueryInput::FromUrl")
                .field("query_id", query_id)
                .field("url", url)
                .finish(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct CompareStatusRequest {
    pub query_id: QueryId,
    pub status: QueryStatus,
}

impl RouteParams<RouteId, QueryId, NoStep> for CompareStatusRequest {
    type Params = String;

    fn resource_identifier(&self) -> RouteId {
        RouteId::QueryStatus
    }

    fn query_id(&self) -> QueryId {
        self.query_id
    }

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        serde_json::to_string(self).unwrap()
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestMultiply,
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestAddInPrimeField,
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestShardedShuffle,
    SemiHonestOprfIpa(IpaQueryConfig),
    MaliciousOprfIpa(IpaQueryConfig),
    MaliciousHybrid(HybridQueryParams),
}

impl QueryType {
    /// TODO: strum
    pub const TEST_MULTIPLY_STR: &'static str = "test-multiply";
    pub const TEST_ADD_STR: &'static str = "test-add";
    pub const TEST_SHARDED_SHUFFLE_STR: &'static str = "test-sharded-shuffle";
    pub const SEMI_HONEST_OPRF_IPA_STR: &'static str = "semi-honest-oprf-ipa";
    pub const MALICIOUS_OPRF_IPA_STR: &'static str = "malicious-oprf-ipa";
    pub const MALICIOUS_HYBRID_STR: &'static str = "malicious-hybrid";
}

/// TODO: should this `AsRef` impl (used for `Substep`) take into account config of IPA?
impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestMultiply => Self::TEST_MULTIPLY_STR,
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestAddInPrimeField => Self::TEST_ADD_STR,
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestShardedShuffle => Self::TEST_SHARDED_SHUFFLE_STR,
            QueryType::SemiHonestOprfIpa(_) => Self::SEMI_HONEST_OPRF_IPA_STR,
            QueryType::MaliciousOprfIpa(_) => Self::MALICIOUS_OPRF_IPA_STR,
            QueryType::MaliciousHybrid(_) => Self::MALICIOUS_HYBRID_STR,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
pub enum DpMechanism {
    NoDp,
    Binomial { epsilon: f64 },
    DiscreteLaplace { epsilon: f64 },
}

#[cfg(test)]
impl Eq for IpaQueryConfig {}

#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct IpaQueryConfig {
    #[cfg_attr(feature = "clap", arg(long, default_value = "8"))]
    pub per_user_credit_cap: u32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_breakdown_key: u32,
    #[cfg_attr(feature = "clap", arg(long))]
    pub attribution_window_seconds: Option<NonZeroU32>,
    #[arg(short = 'd', long, default_value = "1")]
    pub with_dp: u32,
    #[arg(short = 'e', long, default_value = "5.0")]
    pub epsilon: f64,

    /// If false, IPA decrypts match key shares in the input reports. If true, IPA uses match key
    /// shares from input reports directly. Setting this to true also activates an alternate
    /// input report format in which all fields are secret-shared. This option is provided
    /// only for development and testing purposes and may be removed in the future.
    #[cfg_attr(feature = "clap", arg(long))]
    #[serde(default)]
    pub plaintext_match_keys: bool,
}

impl Default for IpaQueryConfig {
    fn default() -> Self {
        Self {
            per_user_credit_cap: 8,
            max_breakdown_key: 20,
            attribution_window_seconds: None,
            with_dp: 1,
            epsilon: 0.10,
            plaintext_match_keys: false,
        }
    }
}

impl IpaQueryConfig {
    /// ## Panics
    /// If attribution window is 0
    #[must_use]
    pub fn new(
        per_user_credit_cap: u32,
        max_breakdown_key: u32,
        attribution_window_seconds: u32,
        with_dp: u32,
        epsilon: f64,
    ) -> Self {
        Self {
            per_user_credit_cap,
            max_breakdown_key,
            attribution_window_seconds: Some(
                NonZeroU32::new(attribution_window_seconds)
                    .expect("attribution window must be a positive value > 0"),
            ),
            with_dp,
            epsilon,
            // dp_params,
            plaintext_match_keys: false,
        }
    }

    /// Creates an IPA query config that does not specify attribution window. That leads to short-cutting
    /// some of the IPA steps inside attribution circuit and getting the answer faster. What it practically
    /// means is that any trigger event can be attributed if there is at least one preceding source event
    /// from the same user in the input.
    #[must_use]
    pub fn no_window(
        per_user_credit_cap: u32,
        max_breakdown_key: u32,
        with_dp: u32,
        epsilon: f64,
    ) -> Self {
        Self {
            per_user_credit_cap,
            max_breakdown_key,
            attribution_window_seconds: None,
            with_dp,
            epsilon,
            plaintext_match_keys: false,
        }
    }
}

#[derive(Serialize, Deserialize, Copy, Clone, PartialEq, Eq, Debug)]
#[serde(try_from = "u32")] // Tell serde to deserialize data into an int and then try to convert it into a valie contributuion bit size
pub struct ContributionBits(u32);

impl TryFrom<u32> for ContributionBits {
    type Error = String;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        match value {
            8 | 32 | 40 => Ok(Self(value)),
            _ => Err(format!(
                "{value} contribution bits is not supported. \
                 Please set to 8, 32, or 40, or add an new implementation."
            )),
        }
    }
}

impl Default for ContributionBits {
    fn default() -> Self {
        Self(8)
    }
}

impl std::fmt::Display for ContributionBits {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
