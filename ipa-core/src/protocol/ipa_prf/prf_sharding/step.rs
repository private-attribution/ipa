use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
#[step(count = 64, child = AttributionPerRowStep, name = "row")]
pub struct UserNthRowStep(usize);

#[derive(CompactStep)]
pub(crate) enum AttributionStep {
    #[step(child = UserNthRowStep)]
    Attribute,
    #[step(child = crate::protocol::context::step::DzkpBatchStep)]
    AttributeValidate,
    #[step(child = crate::protocol::ipa_prf::aggregation::step::AggregationStep)]
    Aggregate,
    #[step(child = crate::protocol::context::step::DzkpSingleBatchStep)]
    AggregateValidate,
}

#[derive(CompactStep)]
pub(crate) enum AttributionPerRowStep {
    EverEncounteredSourceEvent,
    AttributedBreakdownKey,
    #[step(child = AttributionZeroOutTriggerStep)]
    AttributedTriggerValue,
    SourceEventTimestamp,
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    ComputeSaturatingSum,
    IsSaturatedAndPrevRowNotSaturated,
    #[step(child = crate::protocol::boolean::step::EightBitStep)]
    ComputeDifferenceToCap,
    ComputedCappedAttributedTriggerValueNotSaturatedCase,
    ComputedCappedAttributedTriggerValueJustSaturatedCase,
}

#[derive(CompactStep)]
pub(crate) enum AttributionZeroOutTriggerStep {
    DidTriggerGetAttributed,
    #[step(child = AttributionWindowStep)]
    CheckAttributionWindow,
    AttributedEventCheckFlag,
}

#[derive(CompactStep)]
pub(crate) enum AttributionWindowStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    ComputeTimeDelta,
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    CompareTimeDeltaToAttributionWindow,
}

#[derive(CompactStep)]
pub(crate) enum FeatureLabelDotProductStep {
    BinaryValidator,
    PrimeFieldValidator,
    EverEncounteredTriggerEvent,
    DidSourceReceiveAttribution,
    ComputeSaturatingSum,
    IsAttributedSourceAndPrevRowNotSaturated,
}
