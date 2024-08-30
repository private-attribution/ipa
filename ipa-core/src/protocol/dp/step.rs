use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum DPStep {
    #[step(child = crate::protocol::ipa_prf::aggregation::step::AggregationStep)]
    NoiseGen,
    #[step(child = ApplyDpNoise)]
    LaplacePass1,
    #[step(child = ApplyDpNoise)]
    LaplacePass2,
    #[step(child = ApplyDpNoise)]
    LaplacePass3,
}

#[derive(CompactStep)]
pub(crate) enum ApplyDpNoise {
    #[step(child = crate::protocol::boolean::step::ThirtyTwoBitStep)]
    ApplyNoise,
}
