use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::{MaliciousContext, SemiHonestContext};
use crate::protocol::RecordId;
use crate::secret_sharing::{MaliciousReplicated, Replicated, SecretSharing};
use async_trait::async_trait;

pub(crate) mod malicious;
mod semi_honest;
mod sparse;

pub use sparse::{MultiplyZeroPositions, ZeroPositions};

/// Trait to multiply secret shares. That requires communication and `multiply` function is async.
#[async_trait]
pub trait SecureMul<F: Field>: Sized {
    type Share: SecretSharing<F>;

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
    type Share = Replicated<F>;

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
    type Share = MaliciousReplicated<F>;

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

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use rand::Rng;

    use crate::{
        ff::{Field, Fp31},
        secret_sharing::Replicated,
        test_fixture::IntoShares,
    };

    #[derive(Clone, Copy)]
    pub struct SpecializedA(pub Fp31);

    impl IntoShares<Replicated<Fp31>> for SpecializedA {
        fn share_with<R: Rng>(self, _rng: &mut R) -> [Replicated<Fp31>; 3] {
            [
                Replicated::new(self.0, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, self.0),
            ]
        }
    }

    #[derive(Clone, Copy)]
    pub struct SpecializedB(pub Fp31);

    impl IntoShares<Replicated<Fp31>> for SpecializedB {
        fn share_with<R: Rng>(self, _rng: &mut R) -> [Replicated<Fp31>; 3] {
            [
                Replicated::new(Fp31::ZERO, self.0),
                Replicated::new(self.0, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
            ]
        }
    }

    #[derive(Clone, Copy)]
    pub struct SpecializedC(pub Fp31);

    impl IntoShares<Replicated<Fp31>> for SpecializedC {
        fn share_with<R: Rng>(self, _rng: &mut R) -> [Replicated<Fp31>; 3] {
            [
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, self.0),
                Replicated::new(self.0, Fp31::ZERO),
            ]
        }
    }
}
