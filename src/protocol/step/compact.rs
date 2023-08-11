use std::fmt::{Debug, Display, Formatter};

use ipa_macros::Gate;

use super::{Step, StepNarrow};

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
const FALLBACK_STATE: u16 = 65535;
const UPGRADE_SEMI_HONEST_STATE: u16 = 65534;
const QUERY_TYPE_SEMIHONEST_STATE: u16 = 65533;
const QUERY_TYPE_MALICIOUS_STATE: u16 = 65532;
const PRSS_EXCHANGE_STATE: u16 = 65531;

// Hard-coded state map for steps that call `narrow` but never executed.
// Such steps are used in many places in the code base, either for convenience of
// writing compact code, by design, or for tests.
// For example, `semi_honest::Upgraded` implements `UpgradeContext` trait, but it's
// `upgrade` method is never executed. For these steps, we need to provide the state,
// and sub-states that branch off from it, and deliberately ignore them.
fn static_state_map(state: u16, step: &str) -> u16 {
    if state == ROOT_STATE && step.starts_with("run-") {
        // ignore all `run-*` steps
        // we use `starts_with` to avoid regex dependency. should be good enough
        return ROOT_STATE;
    } else if step == crate::protocol::boolean::random_bits_generator::FallbackStep.as_ref() {
        // returning an arbitrary state here works because there are no subsequent narrows.
        // if there were, we would need to do the same as in `UPGRADE_SEMI_HONEST_STATE` below.
        return FALLBACK_STATE;
    } else if step == crate::protocol::context::semi_honest::UpgradeStep.as_ref()
        || step == crate::protocol::ipa::Step::UpgradeMatchKeyBits.as_ref()
        || step == crate::protocol::ipa::Step::UpgradeBreakdownKeyBits.as_ref()
        || step == crate::protocol::modulus_conversion::convert_shares::Step::Upgrade.as_ref()
        || state == UPGRADE_SEMI_HONEST_STATE
    {
        // ignore any upgrade steps in the semi-honest setting.
        // any subsequent narrows from this state will be ignored.
        return UPGRADE_SEMI_HONEST_STATE;
    } else if step == crate::helpers::query::QueryType::SEMIHONEST_IPA_STR {
        return QUERY_TYPE_SEMIHONEST_STATE;
    } else if step == crate::helpers::query::QueryType::MALICIOUS_IPA_STR {
        return QUERY_TYPE_MALICIOUS_STATE;
    } else if step == crate::helpers::prss_protocol::PrssExchangeStep.as_ref() {
        return PRSS_EXCHANGE_STATE;
    }

    panic!("cannot narrow with \"{step}\" from state {state}");
}

// Reverse of `static_state_map` for `Compact::as_ref()`
fn static_reverse_state_map(state: u16) -> &'static str {
    match state {
        ROOT_STATE => "run-0",
        FALLBACK_STATE => crate::protocol::boolean::random_bits_generator::FallbackStep.as_ref(),
        UPGRADE_SEMI_HONEST_STATE => crate::protocol::context::semi_honest::UpgradeStep.as_ref(),
        QUERY_TYPE_SEMIHONEST_STATE => crate::helpers::query::QueryType::SEMIHONEST_IPA_STR,
        QUERY_TYPE_MALICIOUS_STATE => crate::helpers::query::QueryType::MALICIOUS_IPA_STR,
        PRSS_EXCHANGE_STATE => crate::helpers::prss_protocol::PrssExchangeStep.as_ref(),
        _ => panic!("cannot as_ref() from the invalid state {state}"),
    }
}

fn static_deserialize_state_map(s: &str) -> u16 {
    if s == crate::protocol::boolean::random_bits_generator::FallbackStep.as_ref() {
        return FALLBACK_STATE;
    } else if s == crate::protocol::context::semi_honest::UpgradeStep.as_ref() {
        return UPGRADE_SEMI_HONEST_STATE;
    } else if s == crate::helpers::query::QueryType::SEMIHONEST_IPA_STR {
        return QUERY_TYPE_SEMIHONEST_STATE;
    } else if s == crate::helpers::query::QueryType::MALICIOUS_IPA_STR {
        return QUERY_TYPE_MALICIOUS_STATE;
    } else if s == crate::helpers::prss_protocol::PrssExchangeStep.as_ref() {
        return PRSS_EXCHANGE_STATE;
    }

    panic!("cannot deserialize from the invalid step \"{s}\"");
}

trait NoCommsStep: AsRef<str> {}

impl<C: Step + NoCommsStep> StepNarrow<C> for Compact {
    fn narrow(&self, step: &C) -> Self {
        Self(static_state_map(self.0, step.as_ref()))
    }
}

// `src/protocol/boolean/random_bits_generator.rs`
// We create `fallback_ctx` because the underlying bits generator can fail. In reality,
// this only happens in 5/2^32 cases with `Fp32BitPrime` so we need to rely on the static map.
impl NoCommsStep for crate::protocol::boolean::random_bits_generator::FallbackStep {}

// `src/protocol/context/semi_honest.rs`
// Semi-honest implementations of `UpgradedContext::upgrade()` and subsequent
// `UpgradeToMalicious::upgrade()` narrows but these will end up in `UpgradedContext::upgrade_one()`
// or `UpgradedContext::upgrade_sparse()` which both return Ok() and never trigger communications.
impl NoCommsStep for crate::protocol::context::semi_honest::UpgradeStep {}

// src/query/executor.rs - do_query()
// These are only executed in `real-world-infra` for PRSS generation
impl NoCommsStep for crate::helpers::query::QueryType {}

// src/hlpers/prss_protocol.rs - negotiate()
impl NoCommsStep for crate::helpers::prss_protocol::PrssExchangeStep {}

// obsolete steps. should be removed in the future

impl StepNarrow<crate::protocol::boolean::bit_decomposition::Step> for Compact {
    fn narrow(&self, step: &crate::protocol::boolean::bit_decomposition::Step) -> Self {
        panic!(
            "Cannot narrow a boolean::bit_decomposition::Step::{}",
            step.as_ref()
        )
    }
}

impl StepNarrow<crate::protocol::boolean::add_constant::Step> for Compact {
    // BitDecomposition calls this but we don't use BitDecomposition anymore
    fn narrow(&self, step: &crate::protocol::boolean::add_constant::Step) -> Self {
        panic!(
            "Cannot narrow a boolean::add_constant::Step::{}",
            step.as_ref()
        )
    }
}

impl StepNarrow<crate::protocol::boolean::bitwise_equal::Step> for Compact {
    // We don't have any protocol that uses bitwise_equal anymore
    fn narrow(&self, step: &crate::protocol::boolean::bitwise_equal::Step) -> Self {
        panic!(
            "Cannot narrow a boolean::bitwise_equal::Step::{}",
            step.as_ref()
        )
    }
}

impl StepNarrow<crate::protocol::attribution::input::AttributionResharableStep> for Compact {
    // This is used in unit tests only
    fn narrow(
        &self,
        step: &crate::protocol::attribution::input::AttributionResharableStep,
    ) -> Self {
        panic!(
            "Cannot narrow a attribution::input::AttributionResharableStep::{}",
            step.as_ref()
        )
    }
}

//
// steps used in tests
//

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl NoCommsStep for str {}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl NoCommsStep for String {}
