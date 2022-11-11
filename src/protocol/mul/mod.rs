use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::context::ProtocolContext;
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use async_trait::async_trait;

mod malicious;
mod semi_honest;

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<F: Field> {
    type Share: SecretSharing<F>;

    /// Multiply and return the result of `a` * `b`.
    async fn multiply(
        self,
        record_id: RecordId,
        a: Self::Share,
        b: Self::Share,
    ) -> Result<Self::Share, BoxError>;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
pub use {malicious::MaliciouslySecureMul, semi_honest::SemiHonestMul};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for ProtocolContext<'_, Replicated<F>, F> {
    type Share = Replicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: Self::Share,
        b: Self::Share,
    ) -> Result<Self::Share, BoxError> {
        SemiHonestMul::new(self, record_id).execute(a, b).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for ProtocolContext<'_, MaliciousReplicated<F>, F> {
    type Share = MaliciousReplicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: Self::Share,
        b: Self::Share,
    ) -> Result<Self::Share, BoxError> {
        let acc = self.accumulator();
        MaliciouslySecureMul::new(self, record_id, acc)
            .execute(a, b)
            .await
    }
}
