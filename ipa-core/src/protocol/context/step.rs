use ipa_step_derive::CompactStep;

/// Upgrades all use this step to distinguish protocol steps from the step that is used to upgrade inputs.
#[derive(CompactStep)]
#[step(name = "upgrade", child = crate::protocol::basics::mul::step::MaliciousMultiplyStep)]
pub(crate) struct UpgradeStep;

/// Steps used by the validation component of malicious protocol execution.
/// In addition to these, an implicit step is used to initialize the value of `r`.
#[derive(CompactStep)]
pub(crate) enum MaliciousProtocolStep {
    /// For the execution of the malicious protocol.
    #[step(child = crate::protocol::ipa_prf::step::PrfStep)]
    MaliciousProtocol,
    /// The final validation steps.
    #[step(child = ValidateStep)]
    Validate,
}

#[derive(CompactStep)]
pub(crate) enum ValidateStep {
    /// Propagate the accumulated values of `u` and `w`.
    PropagateUAndW,
    /// Reveal the value of `r`, necessary for validation.
    RevealR,
    /// Check that there is no disagreement between accumulated values.
    #[step(child = crate::protocol::basics::step::CheckZeroStep)]
    CheckZero,
}

// This really is only for DZKPs and not for MACs. The MAC protocol uses record IDs to
// count batches. DZKP probably should do the same to avoid the fixed upper limit.
#[derive(CompactStep)]
#[step(count = 592, child = DzkpValidationProtocolStep)]
pub(crate) struct DzkpBatchStep(pub usize);

// This is used when we don't do batched verification, to avoid paying for x256 as many
// steps in compact gate.
#[derive(CompactStep)]
#[step(child = DzkpValidationProtocolStep)]
pub(crate) struct DzkpSingleBatchStep;

#[derive(CompactStep)]
pub(crate) enum DzkpValidationProtocolStep {
    /// Step for proof generation
    GenerateProof,
    /// Step for producing challenge between proof verifiers
    Challenge,
    /// Step for proof verification
    #[step(child = DzkpProofVerifyStep)]
    VerifyProof,
}

#[derive(CompactStep)]
pub(crate) enum DzkpProofVerifyStep {
    /// Step for computing `p * q` between proof verifiers
    PTimesQ,
    /// Step for computing `G_diff` between proof verifiers
    Diff,
}
