#[cfg(feature = "compact-gate")]
mod compact;
#[cfg(feature = "descriptive-gate")]
mod descriptive;

#[cfg(feature = "compact-gate")]
pub use compact::Compact;
#[cfg(feature = "descriptive-gate")]
pub use descriptive::Descriptive;
use ipa_macros::Step;

#[cfg(feature = "descriptive-gate")]
pub type Gate = descriptive::Descriptive;
#[cfg(feature = "compact-gate")]
pub type Gate = compact::Compact;

pub trait StepNarrow<S: Step + ?Sized> {
    #[must_use]
    fn narrow(&self, step: &S) -> Self;
}

/// Defines a unique step of the IPA protocol at a given level of implementation.
///
/// Any stage of the protocol execution will involve multiple steps.  Each of these steps
/// then might involve executing a process that can be broken down into further steps.
/// Ultimately, there will be processes that need to invoke functions on a PRSS or send
/// data to another helper that needs to be uniquely identified.
///
/// Steps are therefore composed into a hierarchy where top-level steps describe major
/// building blocks for a protocol (such as sort shares, convert shares, apply DP, etc...),
/// intermediate processes describe reusable processes (like shuffling), and steps at the
/// lowest level unique identify multiplications.
///
/// Steps are therefore composed into a `UniqueStepIdentifier`, which collects the complete
/// hierarchy of steps at each layer into a unique identifier.
pub trait Step: AsRef<str> {}

// In test code, allow a string (or string reference) to be used as a `Step`.
// Note: Since the creation of the `derive(Step)` macro, hardly any code is
// required to define a step. Doing so is highly encouraged, even in tests.
#[cfg(test)]
impl Step for String {}

#[cfg(test)]
impl Step for str {}

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

#[derive(Step)]
pub enum EightBitStep {
    #[dynamic(8)]
    Bit(usize),
}

impl From<usize> for EightBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

impl BitStep for EightBitStep {
    fn max_bit_depth() -> u32 {
        8
    }
}

#[derive(Step)]
pub enum SixteenBitStep {
    #[dynamic(16)]
    Bit(usize),
}

impl From<usize> for SixteenBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

impl BitStep for SixteenBitStep {
    fn max_bit_depth() -> u32 {
        16
    }
}

#[derive(Step)]
pub enum ThirtyTwoBitStep {
    #[dynamic(32)]
    Bit(usize),
}

impl From<usize> for ThirtyTwoBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

impl BitStep for ThirtyTwoBitStep {
    fn max_bit_depth() -> u32 {
        32
    }
}

#[derive(Step)]
pub enum TwoHundredFiftySixBitOpStep {
    #[dynamic(256)]
    Bit(usize),
}

impl BitStep for TwoHundredFiftySixBitOpStep {
    fn max_bit_depth() -> u32 {
        256
    }
}

impl From<usize> for TwoHundredFiftySixBitOpStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[cfg(test)]
#[derive(Step)]
pub enum DefaultBitStep {
    #[dynamic(256)]
    Bit(usize),
}

#[cfg(test)]
impl From<usize> for DefaultBitStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

#[cfg(test)]
impl BitStep for DefaultBitStep {
    fn max_bit_depth() -> u32 {
        256
    }
}
