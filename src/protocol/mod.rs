pub mod aggregation;
pub mod attribution;
pub mod basics;
pub mod boolean;
pub mod context;
pub mod dp;
pub mod ipa;
pub mod modulus_conversion;
pub mod prf_sharding;
pub mod prss;
pub mod sort;
pub mod step;

use std::{
    fmt::{Debug, Display, Formatter},
    hash::Hash,
    ops::{Add, AddAssign},
};

pub use basics::BasicProtocols;

use crate::{
    error::Error,
    ff::{Gf20Bit, Gf3Bit, Gf40Bit, Gf8Bit},
};

pub type MatchKey = Gf40Bit;
pub type BreakdownKey = Gf8Bit;
pub type TriggerValue = Gf3Bit;
pub type Timestamp = Gf20Bit;

/// Unique identifier of the MPC query requested by report collectors
/// TODO(615): Generating this unique id may be tricky as it may involve communication between helpers and
/// them collaborating on constructing this unique id. These details haven't been flushed out yet,
/// so for now it is just an empty struct. Once we know more about it, we will make necessary
/// amendments to it
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(into = "&'static str", try_from = "&str")
)]
pub struct QueryId;

impl Display for QueryId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // fail when query id becomes meaningful and change the display implementation
        let _: QueryId = QueryId;
        write!(f, "{self:?}")
    }
}

impl QueryId {
    fn repr() -> &'static str {
        "0"
    }
}

impl AsRef<str> for QueryId {
    fn as_ref(&self) -> &str {
        QueryId::repr()
    }
}

impl From<QueryId> for &'static str {
    fn from(_: QueryId) -> Self {
        QueryId::repr()
    }
}

impl TryFrom<&str> for QueryId {
    type Error = Error;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        if value == QueryId::repr() {
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

impl Display for RecordId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

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

impl RecordId {
    pub(crate) const FIRST: Self = Self(0);
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

impl Add<usize> for RecordId {
    type Output = Self;

    fn add(self, rhs: usize) -> Self::Output {
        RecordId::from(usize::try_from(self.0).unwrap() + rhs)
    }
}

impl AddAssign<usize> for RecordId {
    fn add_assign(&mut self, rhs: usize) {
        self.0 += u32::try_from(rhs).unwrap();
    }
}

/// Helper used when an operation may or may not be associated with a specific record. This is
/// also used to prevent some kinds of invalid uses of record ID iteration. For example, trying to
/// use the record ID to iterate over both the inner and outer vectors in a `Vec<Vec<T>>` is an
/// error. Instead, one level of iteration can use the record ID and the other can use something
/// like a `BitOpStep`.
///
/// There are some doc tests on `UpgradeContext` showing the use of `RecordBinding`.
pub trait RecordBinding: Copy + Send + Sync + 'static {}

#[derive(Clone, Copy)]
pub struct NoRecord;
impl RecordBinding for NoRecord {}

impl RecordBinding for RecordId {}
