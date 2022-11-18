use std::borrow::Cow;
use std::marker::PhantomData;
use std::sync::Arc;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{ContextInner, MaliciousProtocolContext, ProtocolContext};
use crate::protocol::malicious::SecurityValidatorAccumulator;
use crate::protocol::{Step, Substep};
use crate::protocol::prss::{Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness};
use crate::secret_sharing::Replicated;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestProtocolContext<'a, F: Field> {
    inner: Cow<'a, ContextInner<'a>>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestProtocolContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: Cow::Owned(ContextInner::new(role, participant, gateway)),
            _marker: PhantomData::default(),
        }
    }

    pub(super) fn from_inner(inner: Cow<'a, ContextInner<'a>>) -> Self {
        Self {
            inner,
            _marker: PhantomData::default(),
        }
    }

    #[must_use]
    pub fn upgrade_to_malicious(
        self,
        accumulator: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> MaliciousProtocolContext<'a, F> {
        MaliciousProtocolContext::from_inner(self.inner, accumulator, r_share)
    }
}

impl<'a, F: Field> ProtocolContext<F> for SemiHonestProtocolContext<'a, F> {
    type Share = Replicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Cow::Owned(self.inner.narrow(step)),
            _marker: PhantomData::default(),
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
