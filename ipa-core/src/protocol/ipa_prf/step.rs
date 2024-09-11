use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum IpaPrfStep {
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="padding_dp")]
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::OPRFShuffleStep)]
    Shuffle,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::Fp25519ConversionStep)]
    ConvertFp25519,
    #[step(child = crate::protocol::context::step::DzkpBatchStep)]
    ConvertFp25519Validate,
    PrfKeyGen,
    #[step(child = crate::protocol::context::step::MaliciousProtocolStep)]
    EvalPrf,
    #[step(child = QuicksortStep)]
    SortByTimestamp,
    #[step(child = crate::protocol::ipa_prf::prf_sharding::step::AttributionStep)]
    Attribution,
    #[step(child = crate::protocol::dp::step::DPStep, name = "dp")]
    DifferentialPrivacy,
    #[step(child = crate::protocol::context::step::DzkpSingleBatchStep)]
    DifferentialPrivacyValidate,
}

#[derive(CompactStep)]
pub(crate) enum QuicksortStep {
    /// Sort up to 1B rows. We can't exceed that limit for other reasons as well `record_id`.
    #[step(count = 30, child = crate::protocol::ipa_prf::step::QuicksortPassStep)]
    QuicksortPass(usize),
    #[step(count = 30, child = crate::protocol::context::step::DzkpSingleBatchStep)]
    QuicksortPassValidate(usize),
}

#[derive(CompactStep)]
pub(crate) enum QuicksortPassStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    Compare,
    Reveal,
}

#[derive(CompactStep)]
pub(crate) enum PrfStep {
    GenRandomMask,
    #[step(child = crate::protocol::context::step::UpgradeStep)]
    UpgradeY,
    #[step(child = crate::protocol::context::step::UpgradeStep)]
    UpgradeMask,
    #[step(child = crate::protocol::basics::mul::step::MaliciousMultiplyStep)]
    MultMaskWithPRFInput,
    RevealR,
    Revealz,
}
