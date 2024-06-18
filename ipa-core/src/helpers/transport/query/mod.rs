use std::{
    fmt::{Debug, Display, Formatter},
    num::{NonZeroU32, ParseFloatError},
    str::FromStr,
};

use serde::{de, Deserialize, Deserializer, Serialize};

use crate::{
    ff::FieldType,
    helpers::{
        transport::{routing::RouteId, BodyStream, NoQueryId, NoStep},
        GatewayConfig, RoleAssignment, RouteParams,
    },
    protocol::QueryId,
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

impl From<&QueryConfig> for GatewayConfig {
    fn from(_value: &QueryConfig) -> Self {
        // TODO: pick the correct value for active and test it
        Self::default()
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

pub struct QueryInput {
    pub query_id: QueryId,
    pub input_stream: BodyStream,
}

impl Debug for QueryInput {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "query_inputs[{:?}]", self.query_id)
    }
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub enum QueryType {
    #[cfg(any(test, feature = "test-fixture", feature = "cli"))]
    TestMultiply,
    OprfIpa(IpaQueryConfig),
}

impl QueryType {
    pub const TEST_MULTIPLY_STR: &'static str = "test-multiply";
    pub const OPRF_IPA_STR: &'static str = "oprf_ipa";
}

/// TODO: should this `AsRef` impl (used for `Substep`) take into account config of IPA?
impl AsRef<str> for QueryType {
    fn as_ref(&self) -> &str {
        match self {
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestMultiply => Self::TEST_MULTIPLY_STR,
            QueryType::OprfIpa(_) => Self::OPRF_IPA_STR,
        }
    }
}
#[cfg(test)]
impl PartialEq for IpaQueryConfig {
    fn eq(&self, other: &Self) -> bool {
        self.per_user_credit_cap == other.per_user_credit_cap
            && self.max_breakdown_key == other.max_breakdown_key
            && self.attribution_window_seconds == other.attribution_window_seconds
            && self.num_multi_bits == other.num_multi_bits
            && self.dp_params == other.dp_params
            && self.plaintext_match_keys == other.plaintext_match_keys
    }
}

// TODO switch to using an enum
#[derive(Debug, Copy, Clone, Serialize)]
pub enum DPParams {
    TestingWithNoDP,
    WithDP(f64),
}

impl FromStr for DPParams {
    type Err = ParseFloatError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "TestingWithNoDP" {
            Ok(DPParams::TestingWithNoDP)
        } else {
            let parts: Vec<&str> = s.splitn(2, '=').collect();
            if parts.len() == 2 && parts[0] == "WithDP" {
                match parts[1].parse::<f64>() {
                    Ok(value) => Ok(DPParams::WithDP(value)),
                    Err(e) => Err(e),
                }
            } else {
                Err(s.parse::<f64>().unwrap_err())
            }
        }
    }
}

impl From<&str> for DPParams {
    fn from(s: &str) -> Self {
        match s {
            "TestingWithNoDP" => DPParams::TestingWithNoDP,
            other => {
                let parts: Vec<&str> = other.splitn(2, '=').collect();
                if parts.len() == 2 && parts[0] == "WithDP" {
                    match parts[1].parse::<f64>() {
                        Ok(value) => DPParams::WithDP(value),
                        Err(e) => panic!("{e:?}"),
                    }
                } else {
                    panic!("{:?}", s.parse::<f64>().unwrap_err());
                }
            }
        }
    }
}

impl Display for DPParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DPParams::TestingWithNoDP => write!(f, "TestingWithNoDP"),
            DPParams::WithDP(eps) => write!(f, "WithDP={eps}"),
        }
    }
}

impl<'de> Deserialize<'de> for DPParams {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error>
    {
        let value = String::deserialize(deserializer)?;
        println!("**********************************{value}");
        match value.as_str() {
            "TestingWithNoDP" => Ok(DPParams::TestingWithNoDP),
            _ => {
                // Assuming the input is not a string, try to parse it as a WithDP variant by splitting on the "=" character.
                if let Some((_, value)) = value.split_once('=') {
                    let v = value.parse::<f64>().unwrap();
                    Ok(DPParams::WithDP(v))
                } else {
                    Err(de::Error::custom("Invalid input format"))
                }
            }
        }
    }
}

#[cfg(test)]
impl PartialEq<Self> for DPParams {
    fn eq(&self, other: &DPParams) -> bool {
        match (self, other) {
            (DPParams::TestingWithNoDP, DPParams::TestingWithNoDP) => true,
            (DPParams::WithDP(x), DPParams::WithDP(y)) => x == y,
            _ => false,
        }
    }
}

#[cfg(test)]
impl Eq for DPParams {}

#[cfg(test)]
impl Eq for IpaQueryConfig {}

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "clap", derive(clap::Args))]
pub struct IpaQueryConfig {
    #[cfg_attr(feature = "clap", arg(long, default_value = "8"))]
    pub per_user_credit_cap: u32,
    #[cfg_attr(feature = "clap", arg(long, default_value = "5"))]
    pub max_breakdown_key: u32,
    #[cfg_attr(feature = "clap", arg(long))]
    pub attribution_window_seconds: Option<NonZeroU32>,
    #[cfg_attr(feature = "clap", arg(long, default_value = "3"))]
    pub num_multi_bits: u32,

    /// If `TestingWithNoDP` is the value of the `DPParams` enum,
    /// IPA will not add any DP noise to the outputs.
    #[cfg_attr(feature = "clap", arg(long, default_value = "TestingWithNoDP"))]
    pub dp_params: DPParams,

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
            num_multi_bits: 3,
            // dp_params: DPParams::TestingWithNoDP,
            dp_params: DPParams::WithDP(1.1),
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
        num_multi_bits: u32,
        dp_params: DPParams,
    ) -> Self {
        Self {
            per_user_credit_cap,
            max_breakdown_key,
            attribution_window_seconds: Some(
                NonZeroU32::new(attribution_window_seconds)
                    .expect("attribution window must be a positive value > 0"),
            ),
            num_multi_bits,
            dp_params,
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
        num_multi_bits: u32,
        dp_params: DPParams,
    ) -> Self {
        Self {
            per_user_credit_cap,
            max_breakdown_key,
            attribution_window_seconds: None,
            num_multi_bits,
            dp_params,
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
