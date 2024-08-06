use ipa_step_derive::CompactStep;

/// Upgrades all use this step to distinguish protocol steps from the step that is used to upgrade inputs.
#[derive(CompactStep)]
#[step(name = "upgrade")]
pub(crate) struct UpgradeStep;

/// Steps used by the validation component of malicious protocol execution.
/// In addition to these, an implicit step is used to initialize the value of `r`.
#[derive(CompactStep)]
pub(crate) enum MaliciousProtocolStep {
    /// For the execution of the malicious protocol.
    MaliciousProtocol,
    /// The final validation steps.
    Validate,
}

#[derive(CompactStep)]
pub(crate) enum ValidateStep {
    /// Propagate the accumulated values of `u` and `w`.
    PropagateUAndW,
    /// Reveal the value of `r`, necessary for validation.
    RevealR,
    /// Check that there is no disagreement between accumulated values.
    CheckZero,
}

/// Steps used by the validation component of the DZKP
#[derive(CompactStep)]
pub(crate) enum ZeroKnowledgeProofValidateStep {
    /// For the execution of the malicious protocol.
    DZKPMaliciousProtocol,
    /// Step for validating the DZK proof.
    DZKPValidate,
    /// Step for computing `p * q` between proof verifiers
    PTimesQ,
    /// Step for producing challenge between proof verifiers
    Challenge,
    /// Steps for creating a single proof per chunk
    #[step(count = 256)]
    ValidationChunk(usize),
    /// Step for proof generation
    GenerateProof,
    /// Step for proof verification
    VerifyProof,
}
