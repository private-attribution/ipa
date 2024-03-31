use std::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use async_trait::async_trait;

use crate::{
    error::Error,
    helpers::{Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        context::{
            Base, DZKPContext, InstrumentedIndexedSharedRandomness,
            InstrumentedSequentialSharedRandomness,
        },
        step::{Gate, Step, StepNarrow},
    },
    seq_join::SeqJoin,
};

#[derive(Clone)]
pub struct DZKPUpgraded<'a> {
    inner: Base<'a>,
}

impl<'a> DZKPUpgraded<'a> {
    pub(super) fn new(inner: Base<'a>) -> Self {
        Self { inner }
    }
}

impl<'a> super::Context for DZKPUpgraded<'a> {
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

impl<'a> SeqJoin for DZKPUpgraded<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

#[async_trait]
impl<'a> DZKPContext for DZKPUpgraded<'a> {
    fn is_safe(&self) -> Result<(), Error> {
        Ok(())
    }
}

impl Debug for DZKPUpgraded<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DZKPSemiHonestContext")
    }
}
