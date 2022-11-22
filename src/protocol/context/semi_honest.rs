use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{Context, MaliciousContext};
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
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub(super) inner: Arc<ContextInner<'a>>,
    pub(super) step: Step,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway),
            step: Step::default(),
            _marker: PhantomData::default(),
        }
    }

    #[must_use]
    pub fn upgrade_to_malicious(
        self,
        accumulator: SecurityValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> MaliciousContext<'a, F> {
        MaliciousContext::new(&self, accumulator, r_share)
    }
}

impl<'a, F: Field> Context<F> for SemiHonestContext<'a, F> {
    type Share = Replicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.narrow(step),
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

#[derive(Debug)]
pub(super) struct ContextInner<'a> {
    pub role: Role,
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> ContextInner<'a> {
    fn new(role: Role, prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Arc<Self> {
        Arc::new(Self {
            role,
            prss,
            gateway,
        })
    }
}
