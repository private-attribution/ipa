use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum IpaPrfStep {
    ConvertFp25519,
    EvalPrf,
    ConvertInputRowsToPrf,
    Shuffle,
    SortByTimestamp,
}

#[derive(CompactStep)]
pub(crate) enum QuicksortStep {
    #[step(count = 999)]
    QuicksortPass(usize),
    Compare,
    Reveal,
}

#[derive(CompactStep)]
pub(crate) enum PrfStep {
    PRFKeyGen,
    GenRandomMask,
    MultMaskWithPRFInput,
    RevealR,
    Revealz,
}
