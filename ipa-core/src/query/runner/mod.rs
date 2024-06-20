mod oprf_ipa;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_add;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_add::add as test_add;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::execute_test_multiply;

pub(super) use self::oprf_ipa::OprfIpaQuery;
use crate::{error::Error, query::ProtocolResult};

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
