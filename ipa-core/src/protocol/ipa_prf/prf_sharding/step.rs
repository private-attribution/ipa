use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub enum UserNthRowStep {
    #[step(count = 64)]
    Row(usize),
}

impl From<usize> for UserNthRowStep {
    fn from(v: usize) -> Self {
        Self::Row(v)
    }
}

#[derive(CompactStep)]
pub enum BinaryTreeDepthStep {
    #[step(count = 64)]
    Depth(usize),
}

impl From<usize> for BinaryTreeDepthStep {
    fn from(v: usize) -> Self {
        Self::Depth(v)
    }
}

#[derive(CompactStep)]
pub(crate) enum AttributionStep {
    BinaryValidator,
    PrimeFieldValidator,
    EverEncounteredSourceEvent,
    DidTriggerGetAttributed,
    AttributedBreakdownKey,
    AttributedTriggerValue,
    AttributedEventCheckFlag,
    CheckAttributionWindow,
    ComputeTimeDelta,
    CompareTimeDeltaToAttributionWindow,
    SourceEventTimestamp,
    ComputeSaturatingSum,
    IsSaturatedAndPrevRowNotSaturated,
    ComputeDifferenceToCap,
    ComputedCappedAttributedTriggerValueNotSaturatedCase,
    ComputedCappedAttributedTriggerValueJustSaturatedCase,
    ModulusConvertBreakdownKeyBitsAndTriggerValues,
    MoveValueToCorrectBreakdown,
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

impl TryFrom<u32> for BucketStep {
    type Error = String;

    fn try_from(v: u32) -> Result<Self, Self::Error> {
        let val = usize::try_from(v);
        let val = match val {
            Ok(val) => Self::Bit(val),
            Err(error) => panic!("{error:?}"),
        };
        Ok(val)
    }
}

impl From<usize> for BucketStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}
