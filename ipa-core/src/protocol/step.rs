use ipa_step_derive::{CompactGate, CompactStep};

#[derive(CompactStep, CompactGate)]
pub enum ProtocolStep {
    IpaPrf,
    IpaClassic,
    Multiply,
}
