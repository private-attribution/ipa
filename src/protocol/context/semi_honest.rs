use async_trait::async_trait;

use crate::{
    error::Error,
    helpers::{ChannelId, Gateway, Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        basics::{ShareKnownValue, ZeroPositions},
        context::{
            Context, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
            SpecialAccessToUpgradedContext, UpgradableContext, UpgradedContext,
            UpgradedMaliciousContext,
        },
        malicious::{MaliciousValidator, MaliciousValidatorAccumulator, Validator},
        prss::Endpoint as PrssEndpoint,
        RecordId, Step, Substep,
    },
    secret_sharing::replicated::{
        malicious::{DowngradeMalicious, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
    sync::Arc,
};
use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone)]
pub struct Base<'a> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub inner: Arc<ContextInner<'a>>,
    pub step: Step,
    pub total_records: TotalRecords,
}

impl<'a> Base<'a> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_complete(
            participant,
            gateway,
            Step::default(),
            TotalRecords::Unspecified,
        )
    }

    pub fn new_with_total_records(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        total_records: TotalRecords,
    ) -> Self {
        Self::new_complete(participant, gateway, Step::default(), total_records)
    }

    pub(super) fn new_complete(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        step: Step,
        total_records: TotalRecords,
    ) -> Self {
        Self {
            inner: ContextInner::new(participant, gateway),
            step,
            total_records,
        }
    }
}

impl<'a> Context for Base<'a> {
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
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: self.total_records.overwrite(total_records),
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.total_records
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

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.inner
            .gateway
            .get_sender(&ChannelId::new(role, self.step.clone()), self.total_records)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.inner
            .gateway
            .get_receiver(&ChannelId::new(role, self.step.clone()))
    }
}

impl<'a> SeqJoin for Base<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.gateway.config().active_work()
    }
}

#[derive(Clone)]
pub struct SemiHonest<'a> {
    inner: Base<'a>,
}

impl<'a> SemiHonest<'a> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: Base::new(participant, gateway),
        }
    }

    #[cfg(test)]
    pub fn from_base(base: Base<'a>) -> Self {
        Self { inner: base }
    }
}

impl<'a> Context for SemiHonest<'a> {
    fn role(&self) -> Role {
        self.inner.role()
    }

    fn step(&self) -> &Step {
        self.inner.step()
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: self.inner.narrow(step),
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: self.inner.set_total_records(total_records),
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.inner.total_records()
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        self.inner.prss()
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness,
        InstrumentedSequentialSharedRandomness,
    ) {
        self.inner.prss_rng()
    }

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.inner.send_channel(role)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.inner.recv_channel(role)
    }
}

impl<'a> UpgradableContext for SemiHonest<'a> {
    type UpgradedContext<F: ExtendableField> = UpgradedSemiHonest<'a, F>;
    type Validator<F: ExtendableField> = SemiHonestValidator<'a, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        SemiHonestValidator {
            context: UpgradedSemiHonest {
                inner: self.inner,
                _f: PhantomData,
            },
            _f: PhantomData,
        }
    }
}

impl<'a> SeqJoin for SemiHonest<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl Debug for SemiHonest<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestContext")
    }
}

#[derive(Clone)]
pub struct Malicious<'a> {
    inner: Base<'a>,
}

impl<'a> Malicious<'a> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: Base::new(participant, gateway),
        }
    }

    /// Upgrade this context to malicious.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `replicated::semi_honest::AdditiveShare` to `replicated::malicious::AdditiveShare`.
    /// `accumulator` and `r_share` come from a `MaliciousValidator`.
    #[must_use]
    pub fn upgrade<S: Substep + ?Sized, F: ExtendableField>(
        self,
        malicious_step: &S,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> UpgradedMaliciousContext<'a, F> {
        UpgradedMaliciousContext::new(&self.inner, malicious_step, accumulator, r_share)
    }

    pub(crate) fn base_context(self) -> Base<'a> {
        self.inner
    }
}

impl<'a> Context for Malicious<'a> {
    fn role(&self) -> Role {
        self.inner.role()
    }

    fn step(&self) -> &Step {
        self.inner.step()
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: self.inner.narrow(step),
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: self.inner.set_total_records(total_records),
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.inner.total_records()
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        self.inner.prss()
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness,
        InstrumentedSequentialSharedRandomness,
    ) {
        self.inner.prss_rng()
    }

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.inner.send_channel(role)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.inner.recv_channel(role)
    }
}

impl<'a> UpgradableContext for Malicious<'a> {
    type UpgradedContext<F: ExtendableField> = UpgradedMaliciousContext<'a, F>;
    type Validator<F: ExtendableField> = MaliciousValidator<'a, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        MaliciousValidator::new(self)
    }
}

impl<'a> SeqJoin for Malicious<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl Debug for Malicious<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext")
    }
}

pub struct SemiHonestValidator<'a, F: ExtendableField> {
    context: UpgradedSemiHonest<'a, F>,
    _f: PhantomData<F>,
}

#[async_trait]
impl<'a, F: ExtendableField> Validator<SemiHonest<'a>, F> for SemiHonestValidator<'a, F> {
    fn context(&self) -> UpgradedSemiHonest<'a, F> {
        self.context.clone()
    }

    async fn validate<D: DowngradeMalicious>(self, values: D) -> Result<D::Target, Error> {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;
        Ok(values.downgrade().await.access_without_downgrade())
    }
}

impl<F: ExtendableField> Debug for SemiHonestValidator<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestValidator<{:?}>", type_name::<F>())
    }
}

#[derive(Clone)]
pub struct UpgradedSemiHonest<'a, F: ExtendableField> {
    inner: Base<'a>,
    _f: PhantomData<F>,
}

impl<'a, F: ExtendableField> UpgradedSemiHonest<'a, F> {
    fn new(inner: Base<'a>) -> Self {
        Self {
            inner,
            _f: PhantomData,
        }
    }
}

impl<'a, F: ExtendableField> Context for UpgradedSemiHonest<'a, F> {
    fn role(&self) -> Role {
        self.inner.role()
    }

    fn step(&self) -> &Step {
        self.inner.step()
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self::new(self.inner.narrow(step))
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self::new(self.inner.set_total_records(total_records))
    }

    fn total_records(&self) -> TotalRecords {
        self.inner.total_records()
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        self.inner.prss()
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness,
        InstrumentedSequentialSharedRandomness,
    ) {
        self.inner.prss_rng()
    }

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.inner.send_channel(role)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.inner.recv_channel(role)
    }
}

impl<'a, F: ExtendableField> SeqJoin for UpgradedSemiHonest<'a, F> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

#[async_trait]
impl<'a, F: ExtendableField> UpgradedContext<F> for UpgradedSemiHonest<'a, F> {
    type Share = Replicated<F>;

    fn share_known_value(&self, value: F) -> Self::Share {
        Replicated::share_known_value(&self.inner, value)
    }

    async fn upgrade_one(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error> {
        Ok(x)
    }

    #[cfg(test)]
    async fn upgrade_sparse(
        &self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error> {
        Ok(input)
    }
}

impl<'a, F: ExtendableField> SpecialAccessToUpgradedContext<F> for UpgradedSemiHonest<'a, F> {
    type Base = Base<'a>;

    fn accumulate_macs(self, record_id: RecordId, x: &Replicated<F>) {
        // noop
    }

    fn base_context(self) -> Self::Base {
        self.inner.clone()
    }
}

impl<F: ExtendableField> Debug for UpgradedSemiHonest<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestContext<{:?}>", type_name::<F>())
    }
}

pub(super) struct ContextInner<'a> {
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> ContextInner<'a> {
    fn new(prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Arc<Self> {
        Arc::new(Self { prss, gateway })
    }
}
