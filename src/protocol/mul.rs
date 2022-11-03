use std::future::Future;
use   async_trait::async_trait;
use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated, ReplicatedShare};


#[async_trait]
pub trait SecureMul<F: Field> {
    type Share;

    async fn multiply(record_id: RecordId, a: Self::Share, b: Self::Share) -> Result<Self::Share, BoxError>;
}

#[async_trait]
impl <F: Field> SecureMul<F> for crate::protocol::securemul::SecureMul<'_, F> {
    type Share = Replicated<F>;

    async fn multiply(self, a: Self::Share, b: Self::Share) -> Result<Self::Share, BoxError> {
        // self.execute(a, b).await
    }
}

#[async_trait]
impl <F: Field> SecureMul<F> for crate::protocol::maliciously_secure_mul::MaliciouslySecureMul<'_, F> {
    type Share = MaliciousReplicated<F>;

    async fn multiply(self, a: Self::Share, b: Self::Share) -> Result<Self::Share, BoxError> {
        self.execute(a, b).await
    }
}