extern crate ipa_macros;

use super::{Descriptive, Step, StepNarrow};
use ipa_macros::Gate;
use std::fmt::{Debug, Display, Formatter};

#[derive(Gate, Clone, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(from = "&str")
)]
pub struct Compact(pub u16);

impl Default for Compact {
    fn default() -> Self {
        Self(0)
    }
}

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

// Hard-coded state map for steps that are narrows but never executed.
// Such steps are used in many places in the code base, either for convenience of
// writing compact code, by design, or for tests.
// For example, `semi_honest::Upgraded` implements `UpgradeContext` trait, but it's
// `upgrade` method is never executed. For these steps, we need to provide the state,
// and sub-states that branch off from it, and deliberately ignore them.
fn static_state_map(state: u16, step: &str) -> u16 {
    const ROOT: u16 = 0;
    const FALLBACK: u16 = 65535;
    const UPGRADE_SEMI_HONEST: u16 = 65534;

    match (state, step) {
        // root step
        // TODO: will need to be updated to match regex "run-\d+" but what should the ID be?
        (_, "run-0") => ROOT,

        // RBG fallback narrow
        (_, "fallback") => FALLBACK,

        // semi-honest's dummy narrow in `UpgradeContext::upgrade()`
        (_, "upgrade_semi-honest") => UPGRADE_SEMI_HONEST,
        (UPGRADE_SEMI_HONEST, _) => UPGRADE_SEMI_HONEST, // any subsequent narrows will be ignored

        _ => panic!("cannot narrow with \"{}\" from state {}", step, state),
    }
}

// Reverse of `static_state_map` for `Compact::as_ref()`
fn static_reverse_state_map(state: u16) -> &'static str {
    match state {
        0 => "run-0",
        65535 => "fallback",
        65534 => "upgrade_semi-honest",
        _ => panic!("cannot as_ref() from the invalid state {}", state),
    }
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
impl From<Descriptive> for Compact {
    fn from(_: Descriptive) -> Self {
        panic!("Cannot narrow a descriptive step to compact step")
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
