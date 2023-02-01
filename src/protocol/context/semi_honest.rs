//! Context for protocol executions suitable for semi-honest security model, i.e. secure against
//! honest-but-curious adversary parties.

use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh, TotalRecords};
use crate::helpers::Role;
use crate::protocol::context::{
    Context, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
    MaliciousContext, MaliciousContextBuf,
};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::{Step, Substep};
use crate::secret_sharing::replicated::semi_honest::AdditiveShare as Replicated;

use once_cell::sync::OnceCell;
use std::marker::PhantomData;

#[derive(Debug)]
pub struct ContextStore<'a> {
    pub(super) static_data: ContextStatic<'a>,
    // Ensure that the struct is invariant over 'a, because that may be required in the future.
    pub(super) _dummy: PhantomData<OnceCell<&'a ()>>,
}

impl<'a> ContextStore<'a> {
    fn new(prss: &'a PrssEndpoint, gateway: &'a Gateway) -> ContextStore<'a> {
        ContextStore {
            static_data: ContextStatic::new(prss, gateway),
            _dummy: PhantomData,
        }
    }
}

#[derive(Debug)]
pub struct SemiHonestContext<'c, 'a, F: Field> {
    pub(super) store: &'c ContextStore<'a>,
    pub(super) step: Step,
    pub(super) total_records: TotalRecords,
    // Ensure that the struct is invariant over 'a, because that may be required in the future.
    _dummy: PhantomData<OnceCell<&'a ()>>,
    _marker: PhantomData<F>,
}

#[derive(Debug)]
pub struct SemiHonestContextBuf<'a, F: Field> {
    pub(super) store: ContextStore<'a>,
    pub(super) step: Step,
    pub(super) total_records: TotalRecords,
    // Ensure that the struct is invariant over 'a, because that may be required in the future.
    _dummy: PhantomData<OnceCell<&'a ()>>,
    _marker: PhantomData<F>,
}

impl<'c, 'a, F: Field> Clone for SemiHonestContext<'c, 'a, F> {
    fn clone(&self) -> Self {
        Self {
            store: self.store.clone(),
            step: self.step.clone(),
            total_records: self.total_records,
            _dummy: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<'c, 'a, F: Field> From<&'c SemiHonestContextBuf<'a, F>> for SemiHonestContext<'c, 'a, F> {
    fn from(value: &'c SemiHonestContextBuf<'a, F>) -> Self {
        SemiHonestContext {
            store: &value.store,
            step: value.step.clone(),
            total_records: value.total_records,
            _dummy: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<'a, F: Field> SemiHonestContextBuf<'a, F> {
    pub fn get_ref<'c>(&'c self) -> SemiHonestContext<'c, 'a, F>
    {
        SemiHonestContext::from(self)
    }
}

impl<'a, T: Field> SemiHonestContextBuf<'a, T> {
    pub fn update_with<F: for<'x> FnOnce(SemiHonestContext<'x, 'a, T>) -> SemiHonestContext<'x, 'a, T>>(self, f: F) -> Self {
        let ctx = SemiHonestContext {
            store: &self.store,
            step: self.step,
            total_records: self.total_records,
            _dummy: PhantomData,
            _marker: PhantomData,
        };
        let SemiHonestContext {
            step,
            total_records,
            ..
        } = f(ctx);
        SemiHonestContextBuf {
            store: self.store,
            step,
            total_records,
            _dummy: PhantomData,
            _marker: PhantomData,
        }
    }
}

impl<'c, 'a: 'c, F: Field> SemiHonestContext<'c, 'a, F> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> SemiHonestContextBuf<'a, F> {
        SemiHonestContextBuf {
            store: ContextStore::new(participant, gateway),
            step: Step::default(),
            total_records: TotalRecords::Unspecified,
            _dummy: PhantomData,
            _marker: PhantomData,
        }
    }

    // Used by `impl SpecialAccessToMaliciousContext for MaliciousContext`.
    pub(super) fn new_internal(
        store: &'c ContextStore<'a>,
        step: Step,
        total_records: TotalRecords,
    ) -> SemiHonestContext<'c, 'a, F> {
        SemiHonestContext {
            store,
            step,
            total_records,
            _dummy: PhantomData,
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
    ) -> MaliciousContextBuf<'c, 'a, F> {
        // Note: in SpecialAccessToMaliciousContext, we rely on the fact that
        // upgrade_ctx uses the same store. That will need to be updated if
        // something changes.
        let upgrade_ctx = self.narrow(upgrade_step);
        MaliciousContext::new(&self, malicious_step, upgrade_ctx, accumulator, r_share)
    }
}

impl<'c, 'a, F: Field> Context<F> for SemiHonestContext<'c, 'a, F> {
    type Share = Replicated<F>;

    fn role(&self) -> Role {
        self.store.static_data.gateway.role()
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            store: self.store.clone(),
            step: self.step.narrow(step),
            total_records: self.total_records,
            _marker: PhantomData,
            _dummy: PhantomData,
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
            store: self.store.clone(),
            step: self.step.clone(),
            total_records: total_records.into(),
            _marker: PhantomData,
            _dummy: PhantomData,
        }
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness {
        let prss = self.store.static_data.prss.indexed(self.step());

        InstrumentedIndexedSharedRandomness::new(prss, &self.step, self.role())
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        let (left, right) = self.store.static_data.prss.sequential(self.step());
        (
            InstrumentedSequentialSharedRandomness::new(left, self.step(), self.role()),
            InstrumentedSequentialSharedRandomness::new(right, self.step(), self.role()),
        )
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.store.static_data.gateway.mesh(self.step(), self.total_records)
    }

    fn share_known_value(&self, scalar: F) -> <Self as Context<F>>::Share {
        Replicated::share_known_value(self.role(), scalar)
    }
}

#[derive(Debug)]
pub(super) struct ContextStatic<'a> {
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> ContextStatic<'a> {
    fn new(prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            prss,
            gateway,
        }
    }
}
