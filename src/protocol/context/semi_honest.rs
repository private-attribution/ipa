use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{Context, ContextInner, MaliciousContext};
use crate::protocol::malicious::SecurityValidatorAccumulator;
use crate::protocol::prss::{
    Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness,
};
use crate::protocol::{Step, Substep};
use crate::secret_sharing::Replicated;
use std::marker::PhantomData;
use std::sync::Arc;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestContext<'a, F: Field> {
    inner: ContextInner<'a>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway),
            _marker: PhantomData::default(),
        }
    }

    pub(super) fn from_inner(inner: ContextInner<'a>) -> Self {
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
    ) -> MaliciousContext<'a, F> {
        MaliciousContext::from_inner(self.inner, accumulator, r_share)
    }
}

impl<'a, F: Field> Context<F> for SemiHonestContext<'a, F> {
    type Share = Replicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.inner.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: self.inner.narrow(step),
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

    fn share_of_one(&self) -> <Self as Context<F>>::Share {
        Replicated::one(self.role())
    }
}
