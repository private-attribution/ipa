mod ipa;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
mod test_multiply;

pub(super) use self::ipa::Runner as IpaRunner;
#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
pub(super) use test_multiply::Runner as TestMultiplyRunner;
