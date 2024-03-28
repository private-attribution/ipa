use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum MaliciousMultiplyStep {
    DuplicateMultiply,
    RandomnessForValidation,
    ReshareRx,
}

// This is a dummy step that is used to narrow (but never executed) the semi-honest
// context. Semi-honest implementations of `UpgradedContext::upgrade()` and subsequent
// `UpgradeToMalicious::upgrade()` narrows but these will end up in
// `UpgradedContext::upgrade_one()` or `UpgradedContext::upgrade_sparse()` which both
// return Ok() and never trigger communications.
#[derive(CompactStep)]
#[step(name = "upgrade")]
pub(crate) struct UpgradeStep;
