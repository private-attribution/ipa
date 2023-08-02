#[cfg(feature = "compact-gate")]
mod compact;
#[cfg(feature = "descriptive-gate")]
mod descriptive;

use std::fmt::Debug;

#[cfg(feature = "compact-gate")]
pub use compact::Compact;
#[cfg(feature = "descriptive-gate")]
pub use descriptive::Descriptive;

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

/// A macro that helps in declaring steps that contain a small number of values.
#[macro_export]
macro_rules! repeat64str {
    [$pfx:literal] => {
        repeat64str![$pfx 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50 51 52 53 54 55 56 57 58 59 60 61 62 63]
    };
    [$pfx:literal $($v:literal)*] => {
        [ $(concat!($pfx, stringify!($v))),* ]
    }
}

/// A step generator for bitwise secure operations.
///
/// For each record, we decompose a value into bits (i.e. credits in the
/// Attribution protocol), and execute some binary operations like OR'ing each
/// bit. For each bitwise secure computation, we need to "narrow" the context
/// with a new step to make sure we are using an unique PRSS.
///
/// This is a temporary solution for narrowing contexts until the infra is
/// updated with a new step scheme.
pub struct BitOpStep(usize);

impl Step for BitOpStep {}

impl AsRef<str> for BitOpStep {
    fn as_ref(&self) -> &str {
        const BIT_OP: [&str; 64] = repeat64str!["bit"];
        BIT_OP[self.0]
    }
}

impl From<i32> for BitOpStep {
    fn from(v: i32) -> Self {
        Self(usize::try_from(v).unwrap())
    }
}

impl From<u32> for BitOpStep {
    fn from(v: u32) -> Self {
        Self(usize::try_from(v).unwrap())
    }
}

impl From<usize> for BitOpStep {
    fn from(v: usize) -> Self {
        Self(v)
    }
}

/// Set of steps that define the IPA protocol.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub(crate) enum IpaProtocolStep {
    /// Sort shares by the match key
    Sort(usize),
}

impl Step for IpaProtocolStep {}

impl AsRef<str> for IpaProtocolStep {
    fn as_ref(&self) -> &str {
        const SORT: [&str; 64] = repeat64str!["sort"];

        match self {
            Self::Sort(i) => SORT[*i],
        }
    }
}
