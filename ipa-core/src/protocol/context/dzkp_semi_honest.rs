use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use async_trait::async_trait;
use ipa_step::{Step, StepNarrow};

use crate::{
    error::Error,
    helpers::{
        Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd, ShardReceivingEnd, TotalRecords,
    },
    protocol::{
        context::{
            Base, DZKPContext, InstrumentedIndexedSharedRandomness,
            InstrumentedSequentialSharedRandomness,
        },
        Gate, RecordId,
    },
    seq_join::SeqJoin,
    sharding::{ShardBinding, ShardConfiguration, ShardIndex, Sharded},
};

#[derive(Clone)]
pub struct DZKPUpgraded<'a, B: ShardBinding> {
    inner: Base<'a, B>,
}

impl<'a, B: ShardBinding> DZKPUpgraded<'a, B> {
    pub(super) fn new(inner: Base<'a, B>) -> Self {
        Self { inner }
    }
}

impl ShardConfiguration for DZKPUpgraded<'_, Sharded> {
    fn shard_id(&self) -> ShardIndex {
        self.inner.shard_id()
    }

    fn shard_count(&self) -> ShardIndex {
        self.inner.shard_count()
    }
}

impl<'a> super::ShardedContext for DZKPUpgraded<'a, Sharded> {
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M> {
        self.inner.shard_send_channel(dest_shard)
    }

    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M> {
        self.inner.shard_recv_channel(origin)
    }

    fn cross_shard_prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        self.inner.cross_shard_prss()
    }
}

impl<'a, B: ShardBinding> super::Context for DZKPUpgraded<'a, B> {
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

    fn send_channel<M: MpcMessage>(&self, role: Role) -> SendingEnd<Role, M> {
        self.inner.send_channel(role)
    }

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.inner.recv_channel(role)
    }
}

impl<'a, B: ShardBinding> SeqJoin for DZKPUpgraded<'a, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

#[async_trait]
impl<'a, B: ShardBinding> DZKPContext for DZKPUpgraded<'a, B> {
    async fn validate_record(&self, _record_id: RecordId) -> Result<(), Error> {
        Ok(())
    }
}

impl<B: ShardBinding> Debug for DZKPUpgraded<'_, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DZKPSemiHonestContext<{:?}>", type_name::<B>())
    }
}
