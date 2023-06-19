mod additive_share;

pub use additive_share::{AdditiveShare, Downgrade as DowngradeMalicious, ExtendableField};
pub(crate) use additive_share::{
    ThisCodeIsAuthorizedToDowngradeFromMalicious, UnauthorizedDowngradeWrapper,
};
