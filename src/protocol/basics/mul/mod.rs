use crate::{
    error::Error,
    ff::Field,
    protocol::{
        context::{Context, MaliciousContext, SemiHonestContext},
        RecordId,
    },
    secret_sharing::replicated::{
        malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
    },
};
use async_trait::async_trait;

pub(crate) mod malicious;
mod semi_honest;
pub(in crate::protocol) mod sparse;

pub use sparse::{MultiplyZeroPositions, ZeroPositions};

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<C: Context>: Send + Sync + Sized {
    /// Multiply and return the result of `a` * `b`.
    async fn multiply<'fut>(ctx: C, record_id: RecordId, a: &Self, b: &Self) -> Result<Self, Error>
    where
        C: 'fut,
    {
        Self::multiply_sparse(ctx, record_id, a, b, ZeroPositions::NONE).await
    }

    /// Multiply and return the result of `a` * `b`.
    /// This takes a profile of which helpers are expected to send
    /// in the form (self, left, right).
    /// This is the implementation you should invoke if you want to
    /// save work when you have sparse values.
    async fn multiply_sparse<'fut>(
        ctx: C,
        record_id: RecordId,
        a: &Self,
        b: &Self,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        C: 'fut;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
use {malicious::multiply as malicious_mul, semi_honest::multiply as semi_honest_mul};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: Field> SecureMul<SemiHonestContext<'a>> for Replicated<F> {
    async fn multiply_sparse<'fut>(
        ctx: SemiHonestContext<'a>,
        record_id: RecordId,
        a: &Self,
        b: &Self,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        'a: 'fut,
    {
        semi_honest_mul(ctx, record_id, a, b, zeros_at).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: Field> SecureMul<MaliciousContext<'a, F>> for MaliciousReplicated<F> {
    async fn multiply_sparse<'fut>(
        ctx: MaliciousContext<'a, F>,
        record_id: RecordId,
        a: &Self,
        b: &Self,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        'a: 'fut,
    {
        malicious_mul(ctx, record_id, a, b, zeros_at).await
    }
}
