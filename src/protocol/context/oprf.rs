use std::num::NonZeroUsize;

use crate::{
    helpers::{Gateway, Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        context::{
            Base, InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
        },
        prss::Endpoint as PrssEndpoint,
        step::{Gate, Step, StepNarrow},
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

impl<'a> SeqJoin for Context<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}
