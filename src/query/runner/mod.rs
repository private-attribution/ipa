mod ipa;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

pub(super) use self::ipa::Runner as IpaRunner;
use crate::{error::Error, query::ProtocolResult};
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::Runner as TestMultiplyRunner;

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
