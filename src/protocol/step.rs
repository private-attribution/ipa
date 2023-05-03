use std::fmt::{Debug, Display, Formatter};

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

/// The representation of a unique step in protocol execution.
///
/// This gathers context from multiple layers of execution. Each stage of execution has its
/// own description of the different steps it takes.  Individual components are identified
/// using an implementation of `Step`.  This type combines those with the identifiers from
/// outer functional layers to form this unique identifier.
///
/// This allows each stage of execution to be uniquely identified, while still
/// enabling functional decomposition.
///
/// Underneath, this just takes the string value of each step and concatenates them,
/// with a "/" between each component.
///
/// For example, you might have a high-level process with three steps "a", "b", and "c".
/// Step "a" comprises two actions "x" and "y", but "b" and "c" are atomic actions.
/// Step "a" would be executed with a context identifier of "protocol/a", which it
///  would `narrow()` into "protocol/a/x" and "protocol/a/y" to produce a final set
/// of identifiers: ".../a/x", ".../a/y", ".../b", and ".../c".
///
/// Note that the implementation of this context might change to use a different
/// (possible more efficient) representation.  It is probably not particularly efficient
/// to be cloning this object all over the place.  Of course, a string is pretty useful
/// from a debugging perspective.
#[derive(Clone, Hash, PartialEq, Eq)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(from = "&str")
)]
pub struct Descriptive {
    id: String,
}

impl Display for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.id)
    }
}

impl<S: Step + ?Sized> StepNarrow<S> for Descriptive {
    /// Narrow the scope of the step identifier.
    /// # Panics
    /// In a debug build, this checks that the same refine call isn't run twice and that the string
    /// value of the step doesn't include '/' (which would lead to a bad outcome).
    fn narrow(&self, step: &S) -> Self {
        #[cfg(debug_assertions)]
        {
            let s = String::from(step.as_ref());
            assert!(!s.contains('/'), "The string for a step cannot contain '/'");
        }

        Self {
            id: self.id.clone() + "/" + step.as_ref(),
        }
    }
}

impl Default for Descriptive {
    // TODO(mt): this should might be better if it were to be constructed from
    // a QueryId rather than using a default.
    fn default() -> Self {
        Self {
            id: String::from("protocol"),
        }
    }
}

impl AsRef<str> for Descriptive {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}

impl From<&str> for Descriptive {
    fn from(id: &str) -> Self {
        let id = id.strip_prefix('/').unwrap_or(id);
        Descriptive { id: id.to_owned() }
    }
}

impl Debug for Descriptive {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "step={}", self.id)
    }
}

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
pub enum IpaProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares,
    ModulusConversion(u32),
    /// Sort shares by the match key
    Sort(usize),
    /// Perform attribution.
    Attribution,
    SortPreAccumulation,
}

impl Step for IpaProtocolStep {}

impl AsRef<str> for IpaProtocolStep {
    fn as_ref(&self) -> &str {
        const MODULUS_CONVERSION: [&str; 64] = repeat64str!["mc"];
        const SORT: [&str; 64] = repeat64str!["sort"];

        match self {
            Self::ConvertShares => "convert",
            Self::Sort(i) => SORT[*i],
            Self::ModulusConversion(i) => MODULUS_CONVERSION[usize::try_from(*i).unwrap()],
            Self::Attribution => "attribution",
            Self::SortPreAccumulation => "sort_pre_accumulation",
        }
    }
}
