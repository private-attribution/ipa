use std::fmt::{Debug, Display, Formatter};

use hex::FromHex;

use super::StepNarrow;
use crate::{helpers::{prss_protocol::PrssExchangeStep, query::QueryType}, protocol::step::{GateId, GateIdArray, Step}};

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord, Default)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(from = "&str")
)]
pub struct Compact {
    id: GateId,
}

impl Compact {
    pub fn id(&self) -> &GateId {
        &self.id
    }
}

// serde::Deserialize requires From<&str> implementation
impl From<&str> for Compact {
    fn from(id: &str) -> Self {
        Compact {
            id: GateIdArray::from_hex(id.strip_prefix('/').unwrap_or(id)).unwrap().into(), // TODO use a deser implementation so we can return errors
        }
    }
}

impl Display for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(hex::encode(&self.id).as_str())
    }
}

impl Debug for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "gate[{:?}]={}", &hex::encode(&self.id), &self.to_string())
    }
}

impl<S: Step + ?Sized> StepNarrow<S> for Compact {
    /// Narrow the scope of the step identifier.
    /// # Panics
    /// In a debug build, this checks that the same refine call isn't run twice and that the string
    /// value of the step doesn't include '/' (which would lead to a bad outcome).
    fn narrow(&self, step: &S) -> Self {
        #[cfg(debug_assertions)]
        {
            let s = step.to_string();
            assert!(!s.contains('/'), "The string for a step cannot contain '/'");
        }

        let mut id = self.id.clone();
        #[cfg(all(feature = "step-trace", feature = "in-memory-infra"))]
        {
            id += [std::any::type_name::<S>(), "::"].concat().as_ref();
        }

        id.extend(step.as_bytes());
        #[cfg(feature = "step-trace")]
        {
            metrics::increment_counter!(STEP_NARROWED, STEP => id.clone());
        }

        Self { id }
    }
}

const ROOT_STATE: u16 = 0;
const QUERY_TYPE_OPRF_STATE: u16 = 65533;
const PRSS_EXCHANGE_STATE: u16 = 65532;

/*
impl StepNarrow<QueryType> for Compact {
    fn narrow(&self, step: &QueryType) -> Self {
        match step {
            QueryType::OprfIpa(_) => Self(QUERY_TYPE_OPRF_STATE),
            _ => panic!("cannot narrow from the invalid step {}", step.as_ref()),
        }
    }
}

impl StepNarrow<PrssExchangeStep> for Compact {
    fn narrow(&self, _step: &PrssExchangeStep) -> Self {
        Self(PRSS_EXCHANGE_STATE)
    }
}
*/
