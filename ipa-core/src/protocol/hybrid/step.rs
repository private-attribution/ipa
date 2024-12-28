use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum HybridStep {
    ReshardByTag,
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="report_padding_dp")]
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::ShardedShuffleStep)]
    InputShuffle,
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
    #[step(child = AggregationStep)]
    Aggregate,
    #[step(child = FinalizeSteps)]
    Finalize,
}

#[derive(CompactStep)]
pub(crate) enum AggregateReportsStep {
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    AddBK,
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    AddV,
}

#[derive(CompactStep)]
pub(crate) enum FinalizeSteps {
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedAdditionStep)]
    Add,
    #[step(child = crate::protocol::context::step::DzkpValidationProtocolStep)]
    Validate,
}

#[derive(CompactStep)]
pub(crate) enum AggregationStep {
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="padding_dp")]
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::ShardedShuffleStep)]
    Shuffle,
    Reveal,
    #[step(child = crate::protocol::context::step::DzkpValidationProtocolStep)]
    RevealValidate, // only partly used -- see code
    #[step(count = 4, child = crate::protocol::ipa_prf::aggregation::step::AggregateChunkStep, name = "chunks")]
    Aggregate(usize),
    #[step(count = 4, child = crate::protocol::context::step::DzkpValidationProtocolStep)]
    AggregateValidate(usize),
}
