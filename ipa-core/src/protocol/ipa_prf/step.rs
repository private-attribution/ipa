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
    #[step(child = crate::protocol::dp::step::DPStep, name = "dp")]
    DifferentialPrivacy,
}

#[derive(CompactStep)]
pub(crate) enum ValidationStep {
    PTimesQ,
    Challenge,
}

#[derive(CompactStep)]
pub(crate) enum QuicksortStep {
    /// Sort up to 1B rows. We can't exceed that limit for other reasons as well `record_id`.
    #[step(count = 30, child = crate::protocol::ipa_prf::step::QuicksortPassStep)]
    QuicksortPass(usize),
}

#[derive(CompactStep)]
pub(crate) enum QuicksortPassStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
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
