use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum IpaPrfStep {
    #[step(child = crate::protocol::ipa_prf::shuffle::step::OPRFShuffleStep)]
    Shuffle,
    // ConvertInputRowsToPrf,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::Fp25519ConversionStep)]
    ConvertFp25519,
    #[step(child = PrfStep)]
    EvalPrf,
    #[step(child = QuicksortStep)]
    SortByTimestamp,
    #[step(child = crate::protocol::ipa_prf::prf_sharding::step::AttributionStep)]
    Attribution,
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
