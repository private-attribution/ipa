use std::fmt::{Debug, Display, Formatter};

use ipa_macros::Gate;

use super::StepNarrow;
use crate::helpers::{prss_protocol::PrssExchangeStep, query::QueryType};

#[derive(Gate, Clone, Hash, PartialEq, Eq, Default)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(from = "&str")
)]
pub struct Compact(pub u16);

// serde::Deserialize requires From<&str> implementation
impl From<&str> for Compact {
    fn from(id: &str) -> Self {
        // id begins with '/'. strip it.
        Compact::deserialize(&id[1..])
    }
}

impl Display for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_ref())
    }
}

impl Debug for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "gate[{}]={}", self.0, self.as_ref())
    }
}

const ROOT_STATE: u16 = 0;
const PRSS_EXCHANGE_STATE: u16 = 65531;
const QUERY_TYPE_SEMIHONEST_STATE: u16 = 65533;
const QUERY_TYPE_MALICIOUS_STATE: u16 = 65532;

impl StepNarrow<QueryType> for Compact {
    fn narrow(&self, step: &QueryType) -> Self {
        match step {
            QueryType::SemiHonestIpa(_) => Self(QUERY_TYPE_SEMIHONEST_STATE),
            QueryType::MaliciousIpa(_) => Self(QUERY_TYPE_MALICIOUS_STATE),
            _ => panic!("cannot narrow from the invalid step {}", step.as_ref()),
        }
    }
}

impl StepNarrow<PrssExchangeStep> for Compact {
    fn narrow(&self, _step: &PrssExchangeStep) -> Self {
        Self(PRSS_EXCHANGE_STATE)
    }
}

// Reverse of `static_state_map` for `Compact::as_ref()`
fn static_reverse_state_map(state: u16) -> &'static str {
    match state {
        ROOT_STATE => "run-0",
        QUERY_TYPE_SEMIHONEST_STATE => QueryType::SEMIHONEST_IPA_STR,
        QUERY_TYPE_MALICIOUS_STATE => QueryType::MALICIOUS_IPA_STR,
        PRSS_EXCHANGE_STATE => PrssExchangeStep.as_ref(),
        _ => panic!("cannot as_ref() from the invalid state {state}"),
    }
}

fn static_deserialize_state_map(s: &str) -> u16 {
    if s == "run-0" {
        return ROOT_STATE;
    } else if s == QueryType::SEMIHONEST_IPA_STR {
        return QUERY_TYPE_SEMIHONEST_STATE;
    } else if s == QueryType::MALICIOUS_IPA_STR {
        return QUERY_TYPE_MALICIOUS_STATE;
    } else if s == PrssExchangeStep.as_ref() {
        return PRSS_EXCHANGE_STATE;
    }

    panic!("cannot deserialize from the invalid step \"{s}\"");
}
