use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum GreaterThanConstantStep {
    Reveal,
    CompareLo,
    CompareHi,
    And,
}
