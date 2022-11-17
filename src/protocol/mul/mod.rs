use crate::error::Error;
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
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error>;

    async fn multiply_two_shares_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error>;

    async fn multiply_one_share_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error>;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
pub use {malicious::SecureMul as MaliciouslySecureMul, semi_honest::SecureMul as SemiHonestMul};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for ProtocolContext<'_, Replicated<F>, F> {
    type Share = Replicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        SemiHonestMul::new(self, record_id).execute(a, b).await
    }

    async fn multiply_two_shares_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        SemiHonestMul::new(self, record_id)
            .multiply_two_shares_mostly_zeroes(a, b)
            .await
    }

    async fn multiply_one_share_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        SemiHonestMul::new(self, record_id)
            .multiply_one_share_mostly_zeroes(a, b)
            .await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureMul<F> for ProtocolContext<'_, MaliciousReplicated<F>, F> {
    type Share = MaliciousReplicated<F>;

    async fn multiply(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        let acc = self.accumulator();
        MaliciouslySecureMul::new(self, record_id, acc)
            .execute(a, b)
            .await
    }

    async fn multiply_two_shares_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        let acc = self.accumulator();
        MaliciouslySecureMul::new(self, record_id, acc)
            .multiply_two_shares_mostly_zeroes(a, b)
            .await
    }

    async fn multiply_one_share_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        let acc = self.accumulator();
        MaliciouslySecureMul::new(self, record_id, acc)
            .multiply_one_share_mostly_zeroes(a, b)
            .await
    }
}
