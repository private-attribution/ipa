use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, UpgradedMaliciousContext},
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
    },
};

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

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
use {malicious::multiply as malicious_mul, semi_honest::multiply as semi_honest_mul};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<C: Context, F: Field> SecureMul<C> for Replicated<F> {
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: C,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        C: 'fut,
    {
        semi_honest_mul(ctx, record_id, self, rhs, zeros_at).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: ExtendableField> SecureMul<UpgradedMaliciousContext<'a, F>> for MaliciousReplicated<F> {
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: UpgradedMaliciousContext<'a, F>,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        UpgradedMaliciousContext<'a, F>: 'fut,
    {
        malicious_mul(ctx, record_id, self, rhs, zeros_at).await
    }
}
