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
#[cfg(any(feature = "test-fixture", debug_assertions))]
impl Step for String {}

#[cfg(any(feature = "test-fixture", debug_assertions))]
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
#[derive(Step)]
pub enum BitOpStep {
    #[dynamic(64)]
    Bit(usize),
}

impl From<i32> for BitOpStep {
    fn from(v: i32) -> Self {
        Self::Bit(usize::try_from(v).unwrap())
    }
}

impl From<u32> for BitOpStep {
    fn from(v: u32) -> Self {
        Self::Bit(usize::try_from(v).unwrap())
    }
}

impl From<usize> for BitOpStep {
    fn from(v: usize) -> Self {
        Self::Bit(v)
    }
}

/// Set of steps that define the IPA protocol.
#[derive(Step)]
pub(crate) enum IpaProtocolStep {
    /// Sort shares by the match key
    #[dynamic(64)]
    Sort(usize),
}
