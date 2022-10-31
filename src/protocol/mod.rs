mod attribution;
mod batch;
mod check_zero;
pub mod context;
pub mod malicious;
mod modulus_conversion;
pub mod prss;
mod reveal;
mod reveal_additive_binary;
mod securemul;
pub mod sort;

#[cfg(debug_assertions)]
use std::{
    collections::HashSet,
    sync::{Arc, Mutex},
};
use std::{fmt::Debug, hash::Hash};

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
#[derive(Clone, Debug)]
pub struct UniqueStepId {
    id: String,
    /// This tracks the different values that have been provided to `narrow()`.
    #[cfg(debug_assertions)]
    used: Arc<Mutex<HashSet<String>>>,
}

impl Hash for UniqueStepId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.id.as_bytes());
    }
}

impl PartialEq for UniqueStepId {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}
impl Eq for UniqueStepId {}

impl UniqueStepId {
    /// Narrow the scope of the step identifier.
    /// # Panics
    /// In a debug build, this checks that the same refine call isn't run twice and that the string
    /// value of the step doesn't include '/' (which would lead to a bad outcome).
    #[must_use]
    pub fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self {
        #[cfg(debug_assertions)]
        {
            let s = String::from(step.as_ref());
            assert!(!s.contains('/'), "The string for a step cannot contain '/'");
            assert!(
                self.used.lock().unwrap().insert(s),
                "Refined '{}' with step '{}' twice",
                self.id,
                step.as_ref(),
            );
        }

        Self {
            id: self.id.clone() + "/" + step.as_ref(),
            #[cfg(debug_assertions)]
            used: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl Default for UniqueStepId {
    // TODO(mt): this should might be better if it were to be constructed from
    // a QueryId rather than using a default.
    fn default() -> Self {
        Self {
            id: String::from("protocol"),
            #[cfg(debug_assertions)]
            used: Arc::new(Mutex::new(HashSet::new())),
        }
    }
}

impl AsRef<str> for UniqueStepId {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}

/// Set of steps that define the IPA protocol.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum IpaProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares,
    /// Sort shares by the match key
    Sort,
    /// Perform attribution.
    Attribution,
}

impl Step for IpaProtocolStep {}

impl AsRef<str> for IpaProtocolStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::ConvertShares => "convert",
            Self::Sort => "sort",
            Self::Attribution => "attribution",
        }
    }
}

/// Unique identifier of the MPC query requested by report collectors
/// TODO: Generating this unique id may be tricky as it may involve communication between helpers and
/// them collaborating on constructing this unique id. These details haven't been flushed out yet,
/// so for now it is just an empty struct. Once we know more about it, we will make necessary
/// amendments to it
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct QueryId;

/// Unique identifier of the record inside the query. Support up to `$2^32$` max records because
/// of the assumption that the maximum input is 1B records per query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordId(u32);

pub const RECORD_0: RecordId = RecordId(0);
pub const RECORD_1: RecordId = RecordId(1);
pub const RECORD_2: RecordId = RecordId(2);
pub const RECORD_3: RecordId = RecordId(3);

impl From<u32> for RecordId {
    fn from(v: u32) -> Self {
        RecordId(v)
    }
}

impl From<RecordId> for u128 {
    fn from(r: RecordId) -> Self {
        r.0.into()
    }
}

impl From<RecordId> for u32 {
    fn from(v: RecordId) -> Self {
        v.0
    }
}
