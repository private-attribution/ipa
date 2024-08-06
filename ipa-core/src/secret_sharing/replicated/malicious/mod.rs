mod additive_share;

pub(crate) use additive_share::ThisCodeIsAuthorizedToDowngradeFromMalicious;
pub use additive_share::{
    AdditiveShare, Downgrade as DowngradeMalicious, ExtendableField, ExtendableFieldSimd,
};
