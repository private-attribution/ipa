use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{Context, ContextInner, SemiHonestContext};
use crate::protocol::malicious::SecurityValidatorAccumulator;
use crate::protocol::prss::{
    Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness,
};
use crate::protocol::{Step, Substep};
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use std::sync::Arc;

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousContext<'a, F: Field> {
    inner: ContextInner<'a>,
    accumulator: SecurityValidatorAccumulator<F>,
    r_share: Replicated<F>,
}

impl<'a, F: Field> MaliciousContext<'a, F> {
    pub fn new(
        role: Role,
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway),
            accumulator: acc,
            r_share,
        }
    }

    pub(super) fn from_inner(
        inner: ContextInner<'a>,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner,
            accumulator: acc,
            r_share,
        }
    }

    pub fn accumulator(&self) -> SecurityValidatorAccumulator<F> {
        self.accumulator.clone()
    }

    /// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
    /// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
    /// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
    /// this implementation makes it easier to reinterpret the context as semi-honest.
    ///
    /// The context received will be an exact copy of malicious, so it will be tied up to the same step
    /// and prss.
    #[must_use]
    pub fn to_semi_honest(self) -> SemiHonestContext<'a, F> {
        SemiHonestContext::from_inner(self.inner)
    }
}

impl<'a, F: Field> Context<F> for MaliciousContext<'a, F> {
    type Share = MaliciousReplicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: self.inner.narrow(step),
            accumulator: self.accumulator.clone(),
            // TODO (alex, mt) - is cloning ok here or we need to Cow it?
            r_share: self.r_share.clone(),
        }
    }

    fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.inner.prss.indexed(self.step())
    }

    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.prss.sequential(self.step())
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step())
    }

    fn share_of_one(&self) -> <Self as Context<F>>::Share {
        MaliciousReplicated::one(self.role(), self.r_share.clone())
    }
}
