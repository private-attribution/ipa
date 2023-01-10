use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::{MaliciousContext, SemiHonestContext};
use crate::protocol::RecordId;
use crate::secret_sharing::{
    ArithmeticShare, MaliciousReplicatedAdditiveShares, ReplicatedAdditiveShares, SecretSharing,
};
use async_trait::async_trait;

pub(crate) mod malicious;
mod semi_honest;
pub(in crate::protocol) mod sparse;

pub use sparse::{MultiplyZeroPositions, ZeroPositions};

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<V: ArithmeticShare>: Sized {
    type Share: SecretSharing<V>;

    /// Multiply and return the result of `a` * `b`.
    async fn multiply(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        self.multiply_sparse(record_id, a, b, ZeroPositions::NONE)
            .await
    }

    /// Multiply and return the result of `a` * `b`.
    /// This takes a profile of which helpers are expected to send
    /// in the form (self, left, right).
    /// This is the implementation you should invoke if you want to
    /// save work when you have sparse values.
    async fn multiply_sparse(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self::Share, Error>;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
use {malicious::multiply as malicious_mul, semi_honest::multiply as semi_honest_mul};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for SemiHonestContext<'_, F> {
    type Share = ReplicatedAdditiveShares<F>;

    async fn multiply_sparse(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self::Share, Error> {
        semi_honest_mul(self, record_id, a, b, zeros_at).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicatedAdditiveShares<F>;

    async fn multiply_sparse(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self::Share, Error> {
        malicious_mul(self, record_id, a, b, zeros_at).await
    }
}
