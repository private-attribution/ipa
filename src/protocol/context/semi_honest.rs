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
use crate::sync::Arc;
use crate::telemetry;
use std::marker::PhantomData;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub(super) inner: Arc<ContextInner<'a, F>>,
    pub(super) step: Step,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(
        role: Role,
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        random_bits_generator: &'a RandomBitsGenerator<F>,
    ) -> Self {
        Self {
            inner: ContextInner::new(role, participant, gateway, random_bits_generator),
            step: Step::default(),
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

    fn prss<T>(&self, handler: impl FnOnce(&Arc<IndexedSharedRandomness>) -> T) -> T {
        let _span =
            telemetry::metrics::span!("prss", step = self.step(), role = self.role()).entered();
        let prss = self.inner.prss.indexed(self.step());
        handler(&prss)
    }

    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        let _span =
            telemetry::metrics::span!("prss_rng", step = self.step(), role = self.role()).entered();
        self.inner.prss.sequential(self.step())
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step())
    }

    fn share_of_one(&self) -> <Self as Context<F>>::Share {
        Replicated::one(self.role())
    }

    fn random_bits_generator(&self) -> RandomBitsGenerator<F> {
        // RandomBitsGenerator has only one direct member which is wrapped in
        // `Arc`. This `clone()` will only increment the ref count.
        self.inner.random_bits_generator.clone()
    }
}

#[derive(Debug)]
pub(super) struct ContextInner<'a, F: Field> {
    pub role: Role,
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
    pub random_bits_generator: &'a RandomBitsGenerator<F>,
}

impl<'a, F: Field> ContextInner<'a, F> {
    fn new(
        role: Role,
        prss: &'a PrssEndpoint,
        gateway: &'a Gateway,
        random_bits_generator: &'a RandomBitsGenerator<F>,
    ) -> Arc<Self> {
        Arc::new(Self {
            role,
            prss,
            gateway,
            random_bits_generator,
        })
    }
}
