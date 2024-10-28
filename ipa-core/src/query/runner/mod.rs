#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod add_in_prime_field;
mod hybrid;
mod oprf_ipa;
mod reshard_tag;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use add_in_prime_field::execute as test_add_in_prime_field;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::execute_test_multiply;

pub use self::oprf_ipa::OprfIpaQuery;
use crate::{error::Error, query::ProtocolResult};

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
