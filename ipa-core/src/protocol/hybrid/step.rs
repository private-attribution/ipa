use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum HybridStep {
    ReshardByTag,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="padding_dp")]
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::Fp25519ConversionStep)]
    ConvertFp25519,
    #[step(child = crate::protocol::context::step::DzkpValidationProtocolStep)]
    ConvertFp25519Validate,
    PrfKeyGen,
    #[step(child = crate::protocol::context::step::MaliciousProtocolStep)]
    EvalPrf,
    ReshardByPrf,
    #[step(child = AggregateReportsStep)]
    GroupBySum,
    #[step(child = crate::protocol::context::step::DzkpValidationProtocolStep)]
    GroupBySumValidate,
}

#[derive(CompactStep)]
pub(crate) enum AggregateReportsStep {
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    AddBK,
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    AddV,
}
