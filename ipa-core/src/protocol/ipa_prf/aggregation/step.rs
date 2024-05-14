use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum AggregationStep {
    #[step(child = BucketStep)]
    MoveToBucket,
    #[step(count = 32)]
    Aggregate(usize),
}

#[derive(CompactStep)]
pub enum BucketStep {
    /// should be equal to MAX_BREAKDOWNS
    #[step(count = 512, child = crate::protocol::boolean::step::BoolAndStep)]
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
