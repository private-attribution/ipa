use ipa_step_derive::CompactStep;

// The step count here is duplicated as the AGGREGATE_DEPTH constant in the code.
#[derive(CompactStep)]
#[step(count = 24, child = AggregateValuesStep, name = "fold")]
pub(crate) struct AggregateChunkStep(usize);

#[derive(CompactStep)]
pub(crate) enum AggregateValuesStep {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    Add,
    #[step(child = crate::protocol::ipa_prf::boolean_ops::step::SaturatedAdditionStep)]
    SaturatingAdd,
}
