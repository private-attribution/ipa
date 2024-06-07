use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum DPStep {
    NoiseGen,
    ApplyNoise,
}
