use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum OPRFShuffleStep {
    ApplyPermutations,
    GenerateAHat,
    GenerateBHat,
    GenerateZ,
    TransferCHat,
    TransferX2,
    TransferY1,
    GenerateTags,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::VerifyShuffleStep)]
    VerifyShuffle,
}

#[derive(CompactStep)]
pub(crate) enum VerifyShuffleStep {
    RevealMACKey,
    HashesH3toH1,
    HashH2toH1,
    HashH3toH2,
}
