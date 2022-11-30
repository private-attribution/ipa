pub mod attribution;
mod batch;
pub mod boolean;
mod check_zero;
pub mod context;
pub mod malicious;
mod modulus_conversion;
pub mod mul;
pub mod prss;
mod reveal;
pub mod sort;

use crate::error::Error;
use std::fmt::Debug;
use std::fmt::Formatter;
use std::hash::Hash;
use std::ops::AddAssign;

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
pub trait Substep: AsRef<str> {}

// In test code, allow a string (or string reference) to be used as a `Step`.
#[cfg(any(feature = "test-fixture", debug_assertions))]
impl Substep for String {}

#[cfg(any(feature = "test-fixture", debug_assertions))]
impl Substep for str {}

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
pub struct Step {
    id: String,
}

impl Step {
    /// Narrow the scope of the step identifier.
    /// # Panics
    /// In a debug build, this checks that the same refine call isn't run twice and that the string
    /// value of the step doesn't include '/' (which would lead to a bad outcome).
    #[must_use]
    pub fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
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

impl Default for Step {
    // TODO(mt): this should might be better if it were to be constructed from
    // a QueryId rather than using a default.
    fn default() -> Self {
        Self {
            id: String::from("protocol"),
        }
    }
}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        self.id.as_str()
    }
}

impl From<&str> for Step {
    fn from(id: &str) -> Self {
        let id = id.strip_prefix('/').unwrap_or(id);
        Step { id: id.to_owned() }
    }
}

/// Set of steps that define the IPA protocol.
#[derive(Copy, Clone, PartialEq, Eq, Hash, Debug)]
pub enum IpaProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares,
    /// Sort shares by the match key
    Sort(u32),
    /// Perform attribution.
    Attribution,
    SortPreAccumulation,
}

impl Substep for IpaProtocolStep {}

impl AsRef<str> for IpaProtocolStep {
    fn as_ref(&self) -> &str {
        const SORT: [&str; 64] = [
            "sort0", "sort1", "sort2", "sort3", "sort4", "sort5", "sort6", "sort7", "sort8",
            "sort9", "sort10", "sort11", "sort12", "sort13", "sort14", "sort15", "sort16",
            "sort17", "sort18", "sort19", "sort20", "sort21", "sort22", "sort23", "sort24",
            "sort25", "sort26", "sort27", "sort28", "sort29", "sort30", "sort31", "sort32",
            "sort33", "sort34", "sort35", "sort36", "sort37", "sort38", "sort39", "sort40",
            "sort41", "sort42", "sort43", "sort44", "sort45", "sort46", "sort47", "sort48",
            "sort49", "sort50", "sort51", "sort52", "sort53", "sort54", "sort55", "sort56",
            "sort57", "sort58", "sort59", "sort60", "sort61", "sort62", "sort63",
        ];
        match self {
            Self::ConvertShares => "convert",
            Self::Sort(i) => SORT[usize::try_from(*i).unwrap()],
            Self::Attribution => "attribution",
            Self::SortPreAccumulation => "sort_pre_accumulation",
        }
    }
}

impl Debug for Step {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "step={}", self.id)
    }
}

/// Unique identifier of the MPC query requested by report collectors
/// TODO: Generating this unique id may be tricky as it may involve communication between helpers and
/// them collaborating on constructing this unique id. These details haven't been flushed out yet,
/// so for now it is just an empty struct. Once we know more about it, we will make necessary
/// amendments to it
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(try_from = "&str")
)]
pub struct QueryId;

impl AsRef<str> for QueryId {
    fn as_ref(&self) -> &str {
        "0"
    }
}

impl TryFrom<&str> for QueryId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == "0" {
            Ok(QueryId)
        } else {
            Err(Error::path_parse_error(value))
        }
    }
}

/// Unique identifier of the record inside the query. Support up to `$2^32$` max records because
/// of the assumption that the maximum input is 1B records per query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
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

impl From<usize> for RecordId {
    fn from(v: usize) -> Self {
        RecordId::from(u32::try_from(v).unwrap())
    }
}

/// This implementation exists because I am tired of typing `RecordId::from(0_u32)` in tests.
/// I simply want to be able to say `RecordId::from(0)` there.
#[cfg(test)]
impl From<i32> for RecordId {
    fn from(v: i32) -> Self {
        assert!(v >= 0, "Record identifier must be a non-negative number");

        RecordId::from(u32::try_from(v).unwrap())
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

impl From<RecordId> for usize {
    fn from(r: RecordId) -> Self {
        r.0 as usize
    }
}

impl AddAssign<usize> for RecordId {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += u32::try_from(rhs).unwrap();
    }
}
