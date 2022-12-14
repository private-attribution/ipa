use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::{MaliciousContext, SemiHonestContext};
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use async_trait::async_trait;

pub(crate) mod malicious;
mod semi_honest;

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureSOP<F: Field>: Sized {
    type Share: SecretSharing<F>;

    /// Multiply and return the result of `a` * `b`.
    async fn sum_of_products(
        self,
        record_id: RecordId,
        a: &[&Self::Share],
        b: &[&Self::Share],
        multi_bit_len: usize,
    ) -> Result<Self::Share, Error>;
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
use {
    malicious::sum_of_products as malicious_sops, semi_honest::sum_of_products as semi_honest_sops,
};

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureSOP<F> for SemiHonestContext<'_, F> {
    type Share = Replicated<F>;

    async fn sum_of_products(
        self,
        record_id: RecordId,
        a: &[&Self::Share],
        b: &[&Self::Share],
        multi_bit_len: usize,
    ) -> Result<Self::Share, Error> {
        semi_honest_sops(self, record_id, a, b, multi_bit_len).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> SecureSOP<F> for MaliciousContext<'_, F> {
    type Share = MaliciousReplicated<F>;

    async fn sum_of_products(
        self,
        record_id: RecordId,
        a: &[&Self::Share],
        b: &[&Self::Share],
        multi_bit_len: usize,
    ) -> Result<Self::Share, Error> {
        malicious_sops(self, record_id, a, b, multi_bit_len).await
    }
}
