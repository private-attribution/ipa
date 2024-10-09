use ipa_step_derive::CompactStep;

#[derive(CompactStep)]
#[step(count = 8, name = "bit")]
pub struct EightBitStep(usize);

#[derive(CompactStep)]
#[step(count = 16, name = "bit")]
pub struct SixteenBitStep(usize);

#[derive(CompactStep)]
#[step(count = 32, name = "bit")]
pub struct ThirtyTwoBitStep(usize);

#[derive(CompactStep)]
#[step(count = 256, name = "bit")]
pub struct TwoHundredFiftySixBitOpStep(usize);

#[cfg(test)]
#[derive(CompactStep)]
#[step(count = 256, name = "bit")]
pub struct DefaultBitStep(usize);
