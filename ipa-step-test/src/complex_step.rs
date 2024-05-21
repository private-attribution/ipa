#[path = "inner_step.rs"]
mod inner_step;

use ipa_step_derive::{CompactGate, CompactStep};

use crate::{basic_step::BasicStep, complex_step::inner_step::InnerStep};

#[derive(CompactStep, CompactGate)]
pub enum ComplexStep {
    One,
    #[step(child = BasicStep, count = 10)]
    Two(u8),
    #[step(child = InnerStep)]
    Three,
}
