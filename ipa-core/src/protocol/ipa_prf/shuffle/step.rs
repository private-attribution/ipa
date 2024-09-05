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
    ShuffleProtocol,
    VerifyShuffle,
}
