use std::borrow::Cow;
use std::sync::Arc;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{ContextInner, ProtocolContext, SemiHonestProtocolContext};
use crate::protocol::malicious::SecurityValidatorAccumulator;
use crate::protocol::{Step, Substep};
use crate::protocol::prss::{Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness};
use crate::secret_sharing::{MaliciousReplicated, Replicated};

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousProtocolContext<'a, F: Field> {
    inner: Cow<'a, ContextInner<'a>>,
    accumulator: SecurityValidatorAccumulator<F>,
    r_share: Replicated<F>,
}


impl<'a, F: Field> MaliciousProtocolContext<'a, F> {
    pub fn new(
        role: Role,
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner: Cow::Owned(ContextInner::new(role, participant, gateway)),
            accumulator: acc,
            r_share,
        }
    }

    pub(super) fn from_inner(
        inner: Cow<'a, ContextInner<'a>>,
        acc: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner,
            accumulator: acc,
            r_share,
        }
    }

    pub fn r_share(&self) -> &Replicated<F> {
        &self.r_share
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
    pub fn to_semi_honest(self) -> SemiHonestProtocolContext<'a, F> {
        SemiHonestProtocolContext::from_inner(self.inner)
    }
}

impl<'a, F: Field> ProtocolContext<F> for MaliciousProtocolContext<'a, F> {
    type Share = MaliciousReplicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Cow::Owned(self.inner.narrow(step)),
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
}
