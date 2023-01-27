mod additive_share;

pub use additive_share::{AdditiveShare, Downgrade as DowngradeMalicious};
pub(crate) use additive_share::{
    ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
};
