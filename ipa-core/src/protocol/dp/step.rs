use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum DPStep {
    #[step(child = crate::protocol::ipa_prf::aggregation::step::AggregationStep)]
    NoiseGen,
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    ApplyNoise,
    LaplacePass1,
    LaplacePass2,
    LaplacePass3,
}
