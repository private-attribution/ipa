use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
pub(crate) enum SaturatedAdditionStep {
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
    Add,
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
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
    #[step(child = crate::protocol::boolean::step::BitOpStep)]
    IntegerAddMaskToX,
    #[step(count = 256)]
    RevealY(usize),
}
