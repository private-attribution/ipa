use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum SaturatedAdditionStep {
    Add,
    Select,
}

#[derive(CompactStep)]
pub(crate) enum SaturatedSubtractionStep {
    Subtract,
    Select,
}

#[derive(CompactStep)]
pub(crate) enum Fp25519ConversionStep {
    GenerateSecretSharing,
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
    IntegerAddBetweenMasks,
    IntegerAddMaskToX,
    #[step(count = 256)]
    RevealY(usize),
}
