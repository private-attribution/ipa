use ipa_step_derive::CompactStep;

/// FIXME: This step is not generic enough to be used in the `saturated_addition` protocol.
/// It constrains the input to be at most 2 bytes and it will panic in runtime if it is greater
/// than that. The issue is that compact gate requires concrete type to be put as child.
/// If we ever see it being an issue, we should make a few implementations of this similar to what
/// we've done for bit steps
#[derive(CompactStep)]
pub(crate) enum SaturatedAdditionStep {
    #[step(child = crate::protocol::boolean::step::SixteenBitStep)]
    Add,
    #[step(child = crate::protocol::boolean::step::SixteenBitStep)]
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
    #[step(child = crate::protocol::boolean::step::TwoHundredFiftySixBitOpStep)]
    IntegerAddBetweenMasks,
    #[step(child = crate::protocol::boolean::step::TwoHundredFiftySixBitOpStep)]
    IntegerAddMaskToX,
    #[step(child = crate::protocol::boolean::step::TwoHundredFiftySixBitOpStep)]
    RevealY,
}

#[derive(CompactStep)]
pub(crate) enum MultiplicationStep {
    #[step(child = crate::protocol::boolean::step::SixteenBitStep)]
    Add,
}
