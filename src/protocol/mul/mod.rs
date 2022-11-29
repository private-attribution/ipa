use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::{MaliciousContext, SemiHonestContext};
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
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error>;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
pub use {
    malicious::secure_mul as maliciously_secure_mul, semi_honest::secure_mul as semi_honest_mul,
};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for SemiHonestContext<'_, F> {
    type Share = Replicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        semi_honest_mul(self, record_id, a, b).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        maliciously_secure_mul(self, record_id, a, b).await
    }
}
