use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum AggregationStep {
    MoveToBucket,
    #[step(count = 32)]
    Aggregate(usize),
}
