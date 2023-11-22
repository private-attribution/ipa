use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};

use async_trait::async_trait;
use ipa_macros::Step;

use super::{Context as SuperContext, UpgradeContext, UpgradeToMalicious};
use crate::{
    error::Error,
    helpers::{Gateway, Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        basics::{ShareKnownValue, ZeroPositions},
        context::{
            validator::SemiHonest as Validator, Base, InstrumentedIndexedSharedRandomness,
            InstrumentedSequentialSharedRandomness, SpecialAccessToUpgradedContext,
            UpgradableContext, UpgradedContext,
        },
        prss::Endpoint as PrssEndpoint,
        step::{Gate, Step, StepNarrow},
        NoRecord, RecordId,
    },
    secret_sharing::replicated::{
        malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
};

#[derive(Clone)]
pub struct Context<'a> {
    inner: Base<'a>,
}

impl<'a> Context<'a> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self {
            inner: Base::new(participant, gateway),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn from_base(base: Base<'a>) -> Self {
        Self { inner: base }
    }
}

impl<'a> super::Context for Context<'a> {
    fn role(&self) -> Role {
        self.inner.role()
    }

    fn gate(&self) -> &Gate {
        self.inner.gate()
    }

    fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self
    where
        Gate: StepNarrow<S>,
    {
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

impl<'a> UpgradableContext for Context<'a> {
    type UpgradedContext<F: ExtendableField> = Upgraded<'a, F>;
    type Validator<F: ExtendableField> = Validator<'a, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        Self::Validator::new(self.inner)
    }
}

impl<'a> SeqJoin for Context<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl Debug for Context<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestContext")
    }
}

#[derive(Clone)]
pub struct Upgraded<'a, F: ExtendableField> {
    inner: Base<'a>,
    _f: PhantomData<F>,
}

impl<'a, F: ExtendableField> Upgraded<'a, F> {
    pub(super) fn new(inner: Base<'a>) -> Self {
        Self {
            inner,
            _f: PhantomData,
        }
    }
}

impl<'a, F: ExtendableField> super::Context for Upgraded<'a, F> {
    fn role(&self) -> Role {
        self.inner.role()
    }

    fn gate(&self) -> &Gate {
        self.inner.gate()
    }

    fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self
    where
        Gate: StepNarrow<S>,
    {
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

impl<'a, F: ExtendableField> SeqJoin for Upgraded<'a, F> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

// This is a dummy step that is used to narrow (but never executed) the semi-honest
// context. Semi-honest implementations of `UpgradedContext::upgrade()` and subsequent
// `UpgradeToMalicious::upgrade()` narrows but these will end up in
// `UpgradedContext::upgrade_one()` or `UpgradedContext::upgrade_sparse()` which both
// return Ok() and never trigger communications.
#[derive(Step)]
pub(crate) enum UpgradeStep {
    UpgradeSemiHonest,
}

#[async_trait]
impl<'a, F: ExtendableField> UpgradedContext<F> for Upgraded<'a, F> {
    type Share = Replicated<F>;

    fn share_known_value(&self, value: F) -> Self::Share {
        Replicated::share_known_value(&self.inner, value)
    }

    async fn upgrade_one(
        &self,
        _record_id: RecordId,
        x: Replicated<F>,
        _zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error> {
        Ok(x)
    }

    // Moved from "context/mod.rs" because we want to use the local `UpgradeContext`.
    // `upgrade` for semi-honest is narrowed but never executed. That causes `Compact`
    // gate to panic because it doesn't know anything about state transitions that are
    // not executed. To workaround this, we use a dummy step to narrow the context to
    // let `Compact` gate know that it could be ignored.
    async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        T: Send,
        UpgradeContext<'a, Self, F>: UpgradeToMalicious<'a, T, M>,
    {
        UpgradeContext::new(self.narrow(&UpgradeStep::UpgradeSemiHonest), NoRecord)
            .upgrade(input)
            .await
    }

    async fn upgrade_for<T, M>(&self, record_id: RecordId, input: T) -> Result<M, Error>
    where
        T: Send,
        UpgradeContext<'a, Self, F, RecordId>: UpgradeToMalicious<'a, T, M>,
    {
        UpgradeContext::new(self.narrow(&UpgradeStep::UpgradeSemiHonest), record_id)
            .upgrade(input)
            .await
    }

    #[cfg(test)]
    async fn upgrade_sparse(
        &self,
        input: Replicated<F>,
        _zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error> {
        Ok(input)
    }
}

impl<'a, F: ExtendableField> SpecialAccessToUpgradedContext<F> for Upgraded<'a, F> {
    type Base = Base<'a>;

    fn accumulate_macs(self, _record_id: RecordId, _x: &Replicated<F>) {
        // noop
    }

    fn base_context(self) -> Self::Base {
        self.inner
    }
}

impl<F: ExtendableField> Debug for Upgraded<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SemiHonestContext<{:?}>", type_name::<F>())
    }
}
