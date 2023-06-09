extern crate ipa_macros;

use super::{Step, StepNarrow};
use ipa_macros::Gate;
use std::fmt::{Debug, Display, Formatter};

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
        Compact(id.parse().expect("Failed to parse id {id}"))
    }
}

impl Display for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl Debug for Compact {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "step={}", self.0)
    }
}

const ROOT_STATE: u16 = 0;
const FALLBACK_STATE: u16 = 65535;
const FALLBACK_STEP: &str = "fallback";
const UPGRADE_SEMI_HONEST_STATE: u16 = 65534;
const UPGRADE_SEMI_HONEST_STEP: &str = "upgrade_semi-honest";

// Hard-coded state map for steps that are narrows but never executed.
// Such steps are used in many places in the code base, either for convenience of
// writing compact code, by design, or for tests.
// For example, `semi_honest::Upgraded` implements `UpgradeContext` trait, but it's
// `upgrade` method is never executed. For these steps, we need to provide the state,
// and sub-states that branch off from it, and deliberately ignore them.
fn static_state_map(state: u16, step: &str) -> u16 {
    if state == ROOT_STATE && step.starts_with("run-") {
        // ignore all `run-*` steps
        // we use `starts_with to avoid regex dependency. should be good enough
        return ROOT_STATE;
    } else if step == FALLBACK_STEP {
        // RBG fallback narrow
        return FALLBACK_STATE;
    } else if step == UPGRADE_SEMI_HONEST_STEP || state == UPGRADE_SEMI_HONEST_STATE {
        // semi-honest's dummy narrow in `UpgradeContext::upgrade()`
        // ... and any subsequent narrows from this state will be ignored
        return UPGRADE_SEMI_HONEST_STATE;
    }

    panic!("cannot narrow with \"{step}\" from state {state}");
}

// Reverse of `static_state_map` for `Compact::as_ref()`
fn static_reverse_state_map(state: u16) -> &'static str {
    if state == ROOT_STATE {
        return "run-0";
    } else if state == FALLBACK_STATE {
        return FALLBACK_STEP;
    } else if state == UPGRADE_SEMI_HONEST_STATE {
        return UPGRADE_SEMI_HONEST_STEP;
    }

    panic!("cannot as_ref() from the invalid state {state}");
}

//
// "conditional" steps
//

impl StepNarrow<crate::protocol::context::semi_honest::UpgradeStep> for Compact {
    fn narrow(&self, step: &crate::protocol::context::semi_honest::UpgradeStep) -> Self {
        Self(static_state_map(self.0, step.as_ref()))
    }
}

impl StepNarrow<crate::protocol::boolean::random_bits_generator::FallbackStep> for Compact {
    fn narrow(&self, step: &crate::protocol::boolean::random_bits_generator::FallbackStep) -> Self {
        Self(static_state_map(self.0, step.as_ref()))
    }
}

//
// steps used in tests
//

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<str> for Compact {
    fn narrow(&self, step: &str) -> Self {
        Self(static_state_map(self.0, step))
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<String> for Compact {
    fn narrow(&self, step: &String) -> Self {
        Self(static_state_map(self.0, step.as_str()))
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<crate::helpers::prss_protocol::PrssExchangeStep> for Compact {
    fn narrow(&self, _: &crate::helpers::prss_protocol::PrssExchangeStep) -> Self {
        panic!("Cannot narrow a helpers::prss_protocol::PrssExchangeStep")
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<crate::protocol::boolean::add_constant::Step> for Compact {
    fn narrow(&self, _: &crate::protocol::boolean::add_constant::Step) -> Self {
        panic!("Cannot narrow a boolean::add_constant::Step")
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<crate::protocol::boolean::bit_decomposition::Step> for Compact {
    fn narrow(&self, _: &crate::protocol::boolean::bit_decomposition::Step) -> Self {
        panic!("Cannot narrow a boolean::bit_decomposition::Step")
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<crate::protocol::boolean::bitwise_equal::Step> for Compact {
    fn narrow(&self, _: &crate::protocol::boolean::bitwise_equal::Step) -> Self {
        panic!("Cannot narrow a boolean::bitwise_equal::Step")
    }
}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl StepNarrow<crate::helpers::query::QueryType> for Compact {
    fn narrow(&self, _: &crate::helpers::query::QueryType) -> Self {
        panic!("Cannot narrow a helpers::query::QueryType")
    }
}
