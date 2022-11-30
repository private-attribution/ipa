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

    async fn multiply_one_share_mostly_zeroes(
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
}

/// looks like clippy disagrees with itself on whether this attribute is useless or not.
use {
    malicious::multiply_one_share_mostly_zeroes as maliciously_secure_multiply_one_share_mostly_zeroes,
    malicious::multiply_two_shares_mostly_zeroes as maliciously_secure_multiply_two_shares_mostly_zeroes,
    malicious::secure_mul as maliciously_secure_mul,
    semi_honest::multiply_one_share_mostly_zeroes as semi_honest_multiply_one_share_mostly_zeroes,
    semi_honest::multiply_two_shares_mostly_zeroes as semi_honest_multiply_two_shares_mostly_zeroes,
    semi_honest::secure_mul as semi_honest_mul,
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

    async fn multiply_one_share_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        semi_honest_multiply_one_share_mostly_zeroes(self, record_id, a, b).await
    }

    async fn multiply_two_shares_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        semi_honest_multiply_two_shares_mostly_zeroes(self, record_id, a, b).await
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

    async fn multiply_one_share_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        maliciously_secure_multiply_one_share_mostly_zeroes(self, record_id, a, b).await
    }

    async fn multiply_two_shares_mostly_zeroes(
        self,
        record_id: RecordId,
        a: &Self::Share,
        b: &Self::Share,
    ) -> Result<Self::Share, Error> {
        maliciously_secure_multiply_two_shares_mostly_zeroes(self, record_id, a, b).await
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
