use async_trait::async_trait;

use crate::{
    error::Error,
    protocol::{RecordId, context::UpgradedContext},
};

/// This trait is implemented by secret sharing types that can be upgraded.
/// Upgrade a share only makes sense for MAC-based security as it requires
/// communication between helpers.
///
/// This trait makes the vectorization factor opaque for upgrades.
#[async_trait]
pub trait Upgradable<C: UpgradedContext>: Send {
    type Output;

    /// Upgrades this instance using the specified [`RecordId`].
    /// This method expects context to be configured with
    /// total records.
    ///
    /// ## Errors
    /// When upgrade fails or if context provided does not have
    /// total records setting configured.
    async fn upgrade(self, ctx: C, record_id: RecordId) -> Result<Self::Output, Error>
    where
        C: 'async_trait;
}
