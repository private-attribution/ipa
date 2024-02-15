use async_trait::async_trait;

use crate::{
    error::Error,
    protocol::{context::Context, RecordId},
};

#[cfg(feature = "descriptive-gate")]
pub(crate) mod malicious;
mod semi_honest;
pub(in crate::protocol) mod sparse;

pub use sparse::{MultiplyZeroPositions, ZeroPositions};

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<C: Context>: Send + Sync + Sized {
    /// Multiply and return the result of `a` * `b`.
    async fn multiply<'fut>(&self, rhs: &Self, ctx: C, record_id: RecordId) -> Result<Self, Error>
    where
        C: 'fut,
    {
        self.multiply_sparse(rhs, ctx, record_id, ZeroPositions::NONE)
            .await
    }

    /// Multiply and return the result of `a` * `b`.
    /// This takes a profile of which helpers are expected to send
    /// in the form (self, left, right).
    /// This is the implementation you should invoke if you want to
    /// save work when you have sparse values.
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: C,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        C: 'fut;
}
