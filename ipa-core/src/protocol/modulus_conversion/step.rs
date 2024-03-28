use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum ConvertSharesStep {
    #[step(count = 64)]
    ConvertBit(u32),
    Upgrade,
    Xor1,
    Xor2,
}
