use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub enum UserNthRowStep {
    #[step(count = 64, child = AttributionPerRowStep)]
    Row(usize),
}

impl From<usize> for UserNthRowStep {
    fn from(v: usize) -> Self {
        Self::Row(v)
    }
}

#[derive(CompactStep)]
pub enum BinaryTreeDepthStep {
    #[step(count = 64, child = BucketStep)]
    Depth(usize),
}

impl From<usize> for BinaryTreeDepthStep {
    fn from(v: usize) -> Self {
        Self::Depth(v)
    }
}

#[derive(CompactStep)]
pub(crate) enum AttributionStep {
    #[step(child = UserNthRowStep)]
    BinaryValidator,
    PrimeFieldValidator,
    ModulusConvertBreakdownKeyBitsAndTriggerValues,
    #[step(child = BinaryTreeDepthStep)]
    MoveValueToCorrectBreakdown,
    Aggregate,
}

#[derive(CompactStep)]
pub(crate) enum AttributionPerRowStep {
    EverEncounteredSourceEvent,
    AttributedBreakdownKey,
    #[step(child = AttributionZeroTriggerStep)]
    AttributedTriggerValue,
    SourceEventTimestamp,
    ComputeSaturatingSum,
    IsSaturatedAndPrevRowNotSaturated,
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
    ComputeDifferenceToCap,
    ComputedCappedAttributedTriggerValueNotSaturatedCase,
    ComputedCappedAttributedTriggerValueJustSaturatedCase,
}

#[derive(CompactStep)]
pub(crate) enum AttributionZeroTriggerStep {
    DidTriggerGetAttributed,
    #[step(child = AttributionWindowStep)]
    CheckAttributionWindow,
    AttributedEventCheckFlag,
}

#[derive(CompactStep)]
pub(crate) enum AttributionWindowStep {
    ComputeTimeDelta,
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
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
    ComputedCappedFeatureVector,
    ModulusConvertFeatureVectorBits,
}

#[derive(CompactStep)]
pub enum BucketStep {
    #[step(count = 256)]
    Bit(usize),
}

impl From<u32> for BucketStep {
    fn from(v: u32) -> Self {
        Self::Bit(usize::try_from(v).unwrap())
    }
}

impl From<usize> for BucketStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}
