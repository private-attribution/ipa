mod ipa;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

use crate::{error::Error, query::ProtocolResult};

pub(super) use self::ipa::IpaQuery;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::execute_test_multiply;

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
