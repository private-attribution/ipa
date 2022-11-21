use crate::{
    error::Error,
    ff::Field,
    helpers::Role,
    secret_sharing::{MaliciousReplicated, Replicated, SecretSharing},
};

use super::{
    context::ProtocolContext,
    sort::reshare::{reshare, reshare_malicious},
    RecordId,
};
use async_trait::async_trait;

pub trait ShareOfOne<F: Field> {
    type Share: SecretSharing<F>;
    fn share_of_one(&self) -> Self::Share;
}

impl<F: Field> ShareOfOne<F> for ProtocolContext<'_, Replicated<F>, F> {
    type Share = Replicated<F>;

    fn share_of_one(&self) -> Self::Share {
        Replicated::one(self.role())
    }
}

impl<F: Field> ShareOfOne<F> for ProtocolContext<'_, MaliciousReplicated<F>, F> {
    type Share = MaliciousReplicated<F>;

    fn share_of_one(&self) -> Self::Share {
        MaliciousReplicated::one(self.role(), self.r_share())
    }
}

#[async_trait]
pub trait Reshare<F: Field> {
    type Share: SecretSharing<F>;
    async fn reshare(
        self,
        input: &Self::Share,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error>;
}

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> Reshare<F> for ProtocolContext<'_, Replicated<F>, F> {
    type Share = Replicated<F>;

    async fn reshare(
        self,
        input: &Self::Share,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error> {
        reshare(self, input, record_id, to_helper).await
    }
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<F: Field> Reshare<F> for ProtocolContext<'_, MaliciousReplicated<F>, F> {
    type Share = MaliciousReplicated<F>;
    async fn reshare(
        self,
        input: &Self::Share,
        record_id: RecordId,
        to_helper: Role,
    ) -> Result<Self::Share, Error> {
        reshare_malicious(self, input, record_id, to_helper).await
    }
}
