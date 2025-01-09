#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod add_in_prime_field;
mod hybrid;
mod reshard_tag;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod sharded_shuffle;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use add_in_prime_field::execute as test_add_in_prime_field;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use sharded_shuffle::execute_sharded_shuffle;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::execute_test_multiply;

pub use self::hybrid::execute_hybrid_protocol;
use crate::{error::Error, query::ProtocolResult};

pub(super) type QueryResult = Result<Box<dyn ProtocolResult>, Error>;
