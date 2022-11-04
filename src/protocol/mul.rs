use std::future::Future;
use   async_trait::async_trait;
use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretShare};


#[async_trait]
pub trait SecureMul<F: Field> {
    type Share: SecretShare<F>;

    async fn multiply(self, record_id: RecordId, a: Self::Share, b: Self::Share) -> Result<Self::Share, BoxError>;
}
