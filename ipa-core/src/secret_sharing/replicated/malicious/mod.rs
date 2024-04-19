mod additive_share;

pub(crate) use additive_share::ThisCodeIsAuthorizedToDowngradeFromMalicious;
#[cfg(feature = "descriptive-gate")]
pub(crate) use additive_share::UnauthorizedDowngradeWrapper;
pub use additive_share::{AdditiveShare, Downgrade as DowngradeMalicious, ExtendableField};
