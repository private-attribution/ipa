use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    helpers::{ChannelId, Gateway, Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        basics::ZeroPositions,
        context::{
            Context, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
            MaliciousContext, UpgradeContext, UpgradeToMalicious, UpgradedContext,
        },
        malicious::MaliciousValidatorAccumulator,
        prss::Endpoint as PrssEndpoint,
        RecordId, Step, Substep,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare, ExtendableField},
        semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
    sync::Arc,
};
use std::{
    fmt::{Debug, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};

use super::SpecialAccessToUpgradedContext;

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone)]
pub struct SemiHonestContext<'a> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    pub(super) inner: Arc<ContextInner<'a>>,
    pub(super) step: Step,
    pub(super) total_records: TotalRecords,
}

impl<'a> SemiHonestContext<'a> {
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

    /// Upgrade this context to malicious.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `replicated::semi_honest::AdditiveShare` to `replicated::malicious::AdditiveShare`.
    /// `accumulator` and `r_share` come from a `MaliciousValidator`.
    #[must_use]
    pub fn upgrade<S: Substep + ?Sized, F: Field + ExtendableField>(
        self,
        malicious_step: &S,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> MaliciousContext<'a, F> {
        MaliciousContext::new(&self, malicious_step, accumulator, r_share)
    }
}

impl<'a> Context for SemiHonestContext<'a> {
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

    fn total_records<I: Into<RecordId>>(&self, record_id: I) -> TotalRecords {
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

impl SeqJoin for SemiHonestContext<'_> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.gateway.config().active_work()
    }
}

impl Debug for SemiHonestContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestContext")
    }
}

#[derive(Debug, Clone)]
struct UpgradedSemiHonest<'a, F: Field + ExtendableField> {
    context: SemiHonestContext<'a>,
    _f: PhantomData<F>,
}

impl<'a, F: Field + ExtendableField> UpgradedSemiHonest<'a, F> {
    fn new(context: SemiHonestContext<'a>) -> Self {
        Self {
            context,
            _f: PhantomData,
        }
    }
}

impl<F: Field + ExtendableField> Context for UpgradedSemiHonest<'_, F> {
    fn role(&self) -> Role {
        self.context.role()
    }

    fn step(&self) -> &Step {
        self.context.step()
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self::new(self.context.narrow(step))
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self::new(self.context.set_total_records(total_records))
    }

    fn total_records(&self) -> TotalRecords {
        self.context.total_records()
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness {
        self.context.prss()
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        self.context.prss_rng()
    }

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.context.send_channel(role)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.recv_channel(role)
    }
}

impl<F: Field + ExtendableField> SeqJoin for UpgradedSemiHonest<'_, F> {
    fn active_work(&self) -> NonZeroUsize {
        self.context.active_work()
    }
}

#[async_trait]
impl<'a, F: Field + ExtendableField> UpgradedContext<'a, F> for UpgradedSemiHonest<'a, F> {
    type UpgradedShare = Replicated<F>;

    async fn upgrade_one(
        &self,
        _record_id: RecordId,
        x: Replicated<F>,
        _zeros_at: ZeroPositions,
    ) -> Result<Self::UpgradedShare, Error> {
        Ok(x)
    }

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        UpgradeContext<'a, Self, F>: UpgradeToMalicious<T, M> + 'a,
    {
        Ok(input)
    }

    /// Upgrade a sparse input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    #[cfg(test)]
    async fn upgrade_sparse(
        &self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<Self::UpgradedShare, Error> {
        Ok(input)
    }

    /// Upgrade an input for a specific bit index and record using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade_for<T, M>(&self, record_id: RecordId, input: T) -> Result<M, Error>
    where
        UpgradeContext<'a, Self, F, RecordId>: UpgradeToMalicious<T, M> + 'a,
    {
        Ok(input)
    }

    fn share_known_value(&self, value: F) -> Self::UpgradedShare {
        Replicated::share_known_value(&self.context, value)
    }
}

impl<'a, F: Field + ExtendableField> SpecialAccessToUpgradedContext<'a, F>
    for UpgradedSemiHonest<'a, F>
{
    fn accumulate_macs(self, record_id: RecordId, x: &AdditiveShare<F>) {
        // noop for semi-honest
    }

    fn semi_honest_context(self) -> SemiHonestContext<'a> {
        self.context.clone()
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
