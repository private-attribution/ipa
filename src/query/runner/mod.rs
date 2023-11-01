mod aggregate;
mod ipa;
mod oprf_ipa;
pub mod oprf_shuffle;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::execute_test_multiply;

pub(super) use self::{
    aggregate::SparseAggregateQuery, ipa::IpaQuery, oprf_ipa::OprfIpaQuery,
    oprf_shuffle::query::OPRFShuffleQuery,
};
use crate::{error::Error, query::ProtocolResult};

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
