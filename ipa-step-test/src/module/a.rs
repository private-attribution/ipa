use ipa_step_derive::{CompactGate, CompactStep};

#[derive(CompactStep, CompactGate)]
#[step(child = super::b::Beta)]
pub struct Alpha;
