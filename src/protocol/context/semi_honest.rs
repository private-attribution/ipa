use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh, TotalRecords};
use crate::helpers::Role;
use crate::protocol::context::{
    Context, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
    MaliciousContext,
};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::{Step, Substep};
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;
use crate::sync::Arc;

use std::marker::PhantomData;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone, Debug)]
pub struct SemiHonestContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub(super) inner: Arc<ContextInner<'a>>,
    pub(super) step: Step,
    pub(super) total_records: TotalRecords,
    _marker: PhantomData<F>,
}

impl<'a, F: Field> SemiHonestContext<'a, F> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_with_total_records(participant, gateway, TotalRecords::Unspecified)
    }

    pub fn new_with_total_records(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        total_records: TotalRecords,
    ) -> Self {
        Self {
            inner: ContextInner::new(participant, gateway),
            step: Step::default(),
            total_records,
            _marker: PhantomData,
        }
    }

    /// Upgrade this context to malicious.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `replicated::semi_honest::AdditiveShare` to `replicated::malicious::AdditiveShare`.
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
        self.inner.gateway.role()
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.narrow(step),
            total_records: self.total_records,
            _marker: PhantomData,
        }
    }

    fn is_total_records_unspecified(&self) -> bool {
        self.total_records.is_unspecified()
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        debug_assert!(
            self.is_total_records_unspecified(),
            "attempt to set total_records more than once"
        );
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: total_records.into(),
            _marker: PhantomData,
        }
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness {
        let prss = self.inner.prss.indexed(self.step());

        InstrumentedIndexedSharedRandomness::new(prss, &self.step, self.role())
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        let (left, right) = self.inner.prss.sequential(self.step());
        (
            InstrumentedSequentialSharedRandomness::new(left, self.step(), self.role()),
            InstrumentedSequentialSharedRandomness::new(right, self.step(), self.role()),
        )
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step(), self.total_records)
    }

    fn share_known_value(&self, scalar: F) -> <Self as Context<F>>::Share {
        Replicated::share_known_value(self.role(), scalar)
    }
}

#[derive(Debug)]
pub(super) struct ContextInner<'a> {
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> ContextInner<'a> {
    fn new(prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Arc<Self> {
        Arc::new(Self { prss, gateway })
    }
}
