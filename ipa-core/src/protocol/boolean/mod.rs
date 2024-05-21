use ipa_step::Step;

use crate::protocol::boolean::step::{
    EightBitStep, SixteenBitStep, ThirtyTwoBitStep, TwoHundredFiftySixBitOpStep,
};

pub mod and;
pub mod or;
pub(crate) mod step;

/// A step generator for bitwise secure operations.
///
/// For each record, we decompose a value into bits (i.e. credits in the
/// Attribution protocol), and execute some binary operations like OR'ing each
/// bit. For each bitwise secure computation, we need to "narrow" the context
/// with a new step to make sure we are using an unique PRSS.
///
/// This is a temporary solution for narrowing contexts until the infra is
/// updated with a new step scheme.
pub trait NBitStep: Step + From<usize> {
    const BITS: u32;
}

impl NBitStep for EightBitStep {
    const BITS: u32 = 8;
}

impl NBitStep for SixteenBitStep {
    const BITS: u32 = 16;
}

impl NBitStep for ThirtyTwoBitStep {
    const BITS: u32 = 32;
}

impl NBitStep for TwoHundredFiftySixBitOpStep {
    const BITS: u32 = 256;
}

#[cfg(test)]
impl NBitStep for crate::protocol::boolean::step::DefaultBitStep {
    const BITS: u32 = 256;
}
