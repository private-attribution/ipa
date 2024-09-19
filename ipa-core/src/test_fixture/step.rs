use ipa_step_derive::CompactStep;

/// Provides a unique per-iteration context in tests.
#[derive(CompactStep)]
pub enum TestExecutionStep {
    #[step(count = 999)]
    Iter(usize),
}
