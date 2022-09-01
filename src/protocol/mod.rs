use std::fmt::{Debug, Formatter};
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
pub trait Step: Copy + Clone + Debug + Eq + Hash + Send + 'static {
    #[must_use]
    fn to_path(&self) -> String;

    fn from_path(path_str: &'static str) -> Result<Self, Error>;
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("unknown path part: {0}")]
    PathParse(&'static str),
    #[error("invalid integer: {0}")]
    PathParseInt(#[from] std::num::ParseIntError),
}

/// Set of steps that define the IPA protocol.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum IPAProtocolStep {
    /// Convert from XOR shares to Replicated shares
    ConvertShares(ShareConversionStep),
    /// Sort shares by the match key
    Sort(SortStep),
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ShareConversionStep {
    ShareConversion,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum SortStep {
    Sort,
}

impl IPAProtocolStep {
    const convert_shares_str: &'static str = "convert-shares";

    const sort_str: &'static str = "sort";
}

impl Step for IPAProtocolStep {
    fn to_path(&self) -> String {
        match self {
            IPAProtocolStep::ConvertShares(share_conversion) => {
                format!(
                    "{}/{}",
                    Self::convert_shares_str,
                    share_conversion.to_path()
                )
            }
            IPAProtocolStep::Sort(sort) => format!("{}/{}", Self::sort_str, sort.to_path()),
        }
    }

    fn from_path(path_str: &'static str) -> Result<Self, Error> {
        let path_str = path_str.strip_prefix('/').unwrap_or(path_str);
        let (step, rest) = path_str
            .split_once('/')
            .ok_or_else(|| Error::PathParse(path_str))?;
        match step {
            Self::convert_shares_str => {
                Ok(Self::ConvertShares(ShareConversionStep::from_path(rest)?))
            }
            Self::sort_str => Ok(Self::Sort(SortStep::from_path(rest)?)),
        }
    }
}

impl ShareConversionStep {
    const share_conversion_str: &'static str = "share-conversion";
}
impl Step for ShareConversionStep {
    fn to_path(&self) -> String {
        match self {
            Self::ShareConversion => Self::share_conversion_str.into(),
        }
    }

    fn from_path(path_str: &'static str) -> Result<Self, Error> {
        match path_str {
            Self::share_conversion_str => Ok(Self::ShareConversion),
            other => Err(Error::PathParse(other)),
        }
    }
}

impl SortStep {
    const sort_str: &'static str = "sort";
}

impl Step for SortStep {
    fn to_path(&self) -> String {
        match self {
            Self::Sort => Self::sort_str.into(),
        }
    }

    fn from_path(path_str: &'static str) -> Result<Self, Error> {
        match path_str {
            Self::sort_str => Ok(SortStep::Sort),
            other => Err(Error::PathParse(other)),
        }
    }
}

/// Unique identifier of the MPC query requested by report collectors
/// TODO: Generating this unique id may be tricky as it may involve communication between helpers and
/// them collaborating on constructing this unique id. These details haven't been flushed out yet,
/// so for now it is just an empty struct. Once we know more about it, we will make necessary
/// amendments to it
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Serialize, serde::Deserialize),
    serde(from = "String")
)]
pub struct QueryId;

/// TODO: replace dummy implementation after we figure out how to assign a value
impl std::fmt::Display for QueryId {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.to_string())
    }
}

/// TODO: replace dummy implementation after we figure out how to assign a value
impl From<String> for QueryId {
    fn from(_: String) -> Self {
        QueryId
    }
}

/// Unique identifier of the record inside the query. Support up to `$2^32$` max records because
/// of the assumption that the maximum input is 1B records per query.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
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
