use ipa_step_derive::CompactStep;
#[derive(CompactStep)]
pub(crate) enum AggregationStep {
    /// Shuffle and reveal are used in the aggregation protocol based on revealing breakdown
    /// key. Aggregation based on move to bucket approach does not need them.
    /// When reveal-based aggregation is the default, other steps (such as `MoveToBucket`)
    /// should be deleted
    #[step(child = crate::protocol::ipa_prf::oprf_padding::step::PaddingDpStep, name="padding_dp")]
    PaddingDp,
    #[step(child = crate::protocol::ipa_prf::shuffle::step::OPRFShuffleStep)]
    Shuffle,
    Reveal,
    #[step(child = crate::protocol::context::step::DzkpSingleBatchStep)]
    RevealValidate, // only partly used -- see code
    #[step(count = 4, child = AggregateChunkStep)]
    Aggregate(usize),
    #[step(count = 600, child = crate::protocol::context::step::DzkpSingleBatchStep)]
    AggregateValidate(usize),
}

// The step count here is duplicated as the AGGREGATE_DEPTH constant in the code.
#[derive(CompactStep)]
#[step(count = 24, child = AggregateValuesStep, name = "depth")]
pub(crate) struct AggregateChunkStep(usize);

#[derive(CompactStep)]
pub(crate) enum AggregateValuesStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    Add,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedAdditionStep)]
    SaturatingAdd,
}
