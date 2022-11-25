use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::boolean::random_bits_generator::RandomBitsGenerator;
use crate::protocol::context::{Context, MaliciousContext};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
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
    pub(super) random_bits_generator: RandomBitsGenerator<F>,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(role: Role, participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway),
            step: Step::default(),
            random_bits_generator: RandomBitsGenerator::new(),
            _marker: PhantomData::default(),
        }
    }

    /// Upgrade this context to malicious.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `Replicated` to `MaliciousReplicated`.
    /// `accumulator` and `r_share` come from a `MaliciousValidator`.
    #[must_use]
    pub fn upgrade<S: Substep + ?Sized>(
        self,
        malicious_step: &S,
        upgrade_step: &S,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> MaliciousContext<'a, F> {
        let upgrade_ctx = self.narrow(upgrade_step);
        MaliciousContext::new(&self, malicious_step, upgrade_ctx, accumulator, r_share)
    }

    /// Test use only!
    /// Reuse a provided `RandomBitsGenerator` (rbg).
    /// Each context holds an instance of `rbg`. It is wrapped within an Arc
    /// pointer, so the instance would persist for the lifetime of the context
    /// its in. In unit tests, however, a new context is created each time a
    /// test is run, which makes the rbg buffer useless. Use this method to
    /// provide an existing rbg to use for tests.
    #[must_use]
    pub fn supply_rbg_for_tests(mut self, rbg: RandomBitsGenerator<F>) -> Self {
        self.random_bits_generator = rbg;
        self
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
            random_bits_generator: self.random_bits_generator.clone(),
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

    fn random_bits_generator(&self) -> RandomBitsGenerator<F> {
        self.random_bits_generator.clone()
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
