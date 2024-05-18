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
pub trait BitStep: Step + From<usize> {
    fn max_bit_depth() -> u32;
}

impl BitStep for EightBitStep {
    fn max_bit_depth() -> u32 {
        8
    }
}

impl BitStep for SixteenBitStep {
    fn max_bit_depth() -> u32 {
        16
    }
}

impl BitStep for ThirtyTwoBitStep {
    fn max_bit_depth() -> u32 {
        32
    }
}

impl BitStep for TwoHundredFiftySixBitOpStep {
    fn max_bit_depth() -> u32 {
        256
    }
}

#[cfg(test)]
impl BitStep for crate::protocol::boolean::step::DefaultBitStep {
    fn max_bit_depth() -> u32 {
        256
    }
}
