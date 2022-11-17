use crate::{
    ff::Field,
    secret_sharing::{MaliciousReplicated, Replicated, SecretSharing},
};

use super::context::ProtocolContext;

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
