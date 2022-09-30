pub mod context;
mod securemul;

use crate::error::Error;
use std::fmt::{Debug, Display, Formatter};
use std::hash::Hash;

/// Defines a unique step of the IPA protocol. Step is a transformation that takes an input
/// in form of a share or set of shares and produces the secret-shared output.
///
/// Some examples of what defines a step include sorting secret shares, converting them from
/// one format to another etc.
///
/// Steps may form a hierarchy where top-level steps describe large building blocks for IPA protocol
/// (such as sort shares, convert shares, apply DP, etc) and bottom-level steps are granular enough
/// to be used to uniquely identify multiplications happening concurrently.
///
/// For testing purposes we also implement completely bogus steps that don't make much sense
/// but used to simplify testing of individual components. Those implementations are hidden behind
/// `[cfg(test)]` flag and shouldn't be considered for any purpose except unit testing.
///
/// See `IPAProtocolStep` for a canonical implementation of this trait. Every time we switch to
/// use a new circuit, there will be an additional struct/enum that implements `Step`, but eventually
/// it should converge to a single implementation.
pub trait Step:
    Copy + Clone + Debug + Eq + Hash + Send + Sync + TryFrom<String, Error = Error> + Display + 'static
{
}

/// Set of steps that define the IPA protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IPAProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares(ShareConversionStep),
    /// Sort shares by the match key
    Sort(SortStep),
}

impl IPAProtocolStep {
    const CONVERT_SHARES_STR: &'static str = "convert-shares";
    const SORT_STR: &'static str = "sort";
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ShareConversionStep {}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortStep {}

impl Display for IPAProtocolStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ConvertShares(_) => write!(f, "{}", Self::CONVERT_SHARES_STR),
            Self::Sort(_) => write!(f, "{}", Self::SORT_STR),
        }
    }
}

impl TryFrom<String> for IPAProtocolStep {
    type Error = Error;

    fn try_from(_value: String) -> Result<Self, Self::Error> {
        // cannot initialize from empty enum
        Err(Error::NotFound)
    }
}
impl Step for IPAProtocolStep {}

/// Unique identifier of the MPC query requested by report collectors
/// TODO: Generating this unique id may be tricky as it may involve communication between helpers and
/// them collaborating on constructing this unique id. These details haven't been flushed out yet,
/// so for now it is just an empty struct. Once we know more about it, we will make necessary
/// amendments to it
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "serde",
    derive(serde::Deserialize),
    serde(try_from = "String")
)]
pub struct QueryId;

impl Display for QueryId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        // dummy value for now
        write!(f, "0")
    }
}

impl TryFrom<String> for QueryId {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // dummy value for now
        (value == "0").then_some(QueryId).ok_or(Error::InvalidId)
    }
}

/// Unique identifier of the record inside the query. Support up to `$2^32$` max records because
/// of the assumption that the maximum input is 1B records per query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct RecordId(u32);

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
