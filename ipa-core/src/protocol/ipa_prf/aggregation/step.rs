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
    RevealStep,
    #[step(child = AggregateChunkStep)]
    SumContributions,
    #[step(child = crate::protocol::context::step::DzkpBatchStep)]
    AggregateValidate,
}

/// the number of steps must be kept in sync with `MAX_BREAKDOWNS` defined
/// [here](https://tinyurl.com/mwnbbnj6)
#[derive(CompactStep)]
#[step(count = 512, child = crate::protocol::boolean::step::EightBitStep, name = "b")]
pub struct BucketStep(usize);

#[derive(CompactStep)]
#[step(count = 32, child = AggregateValuesStep, name = "depth")]
pub(crate) struct AggregateChunkStep(usize);

#[derive(CompactStep)]
pub(crate) enum AggregateValuesStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    Add,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedAdditionStep)]
    SaturatingAdd,
}
