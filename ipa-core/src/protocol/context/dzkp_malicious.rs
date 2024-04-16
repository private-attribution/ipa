use std::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use async_trait::async_trait;

use crate::{
    error::Error,
    helpers::{
        ChannelId, Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd,
        ShardReceivingEnd, TotalRecords,
    },
    protocol::{
        context::{
            dzkp_validator::DZKPBatch, prss::InstrumentedIndexedSharedRandomness, Base,
            Context as ContextTrait, DZKPContext, InstrumentedSequentialSharedRandomness,
        },
        prss::Endpoint as PrssEndpoint,
        step::{Gate, Step, StepNarrow},
    },
    seq_join::SeqJoin,
    sharding::ShardIndex,
    sync::Arc,
};

/// Represents protocol context in malicious setting when using zero-knowledge proofs,
/// i.e. secure against one active adversary in 3 party MPC ring.
#[derive(Clone)]
pub struct DZKPUpgraded<'a> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<DZKPUpgradedInner<'a>>,
    gate: Gate,
    total_records: TotalRecords,
}

impl<'a> DZKPUpgraded<'a> {
    pub(super) fn new<S: Step + ?Sized>(
        source: &Base<'a>,
        malicious_step: &S,
        batch: DZKPBatch,
    ) -> Self
    where
        Gate: StepNarrow<S>,
    {
        Self {
            inner: DZKPUpgradedInner::new(source, batch),
            gate: source.gate().narrow(malicious_step),
            total_records: TotalRecords::Unspecified,
        }
    }
}

#[async_trait]
impl<'a> DZKPContext for DZKPUpgraded<'a> {
    fn is_unverified(&self) -> Result<(), Error> {
        if self.inner.batch.is_empty() {
            Ok(())
        } else {
            Err(Error::ContextUnsafe(format!("{self:?}")))
        }
    }
}

impl<'a> super::Context for DZKPUpgraded<'a> {
    fn role(&self) -> Role {
        self.inner.gateway.role()
    }

    fn gate(&self) -> &Gate {
        &self.gate
    }

    fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self
    where
        Gate: StepNarrow<S>,
    {
        Self {
            inner: Arc::clone(&self.inner),
            gate: self.gate.narrow(step),
            total_records: self.total_records,
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            gate: self.gate.clone(),
            total_records: self.total_records.overwrite(total_records),
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.total_records
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        let prss = self.inner.prss.indexed(self.gate());

        InstrumentedIndexedSharedRandomness::new(prss, &self.gate, self.role())
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        let (left, right) = self.inner.prss.sequential(self.gate());
        (
            InstrumentedSequentialSharedRandomness::new(left, self.gate(), self.role()),
            InstrumentedSequentialSharedRandomness::new(right, self.gate(), self.role()),
        )
    }

    fn send_channel<M: MpcMessage>(&self, role: Role) -> SendingEnd<Role, M> {
        self.inner
            .gateway
            .get_mpc_sender(&ChannelId::new(role, self.gate.clone()), self.total_records)
    }

    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M> {
        self.inner.gateway.get_shard_sender(
            &ChannelId::new(dest_shard, self.gate.clone()),
            self.total_records,
        )
    }

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.inner
            .gateway
            .get_mpc_receiver(&ChannelId::new(role, self.gate.clone()))
    }

    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M> {
        self.inner
            .gateway
            .get_shard_receiver(&ChannelId::new(origin, self.gate.clone()))
    }
}

impl<'a> SeqJoin for DZKPUpgraded<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.gateway.config().active_work()
    }
}

impl Debug for DZKPUpgraded<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DZKPMaliciousContext")
    }
}
struct DZKPUpgradedInner<'a> {
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    batch: DZKPBatch,
}

impl<'a> DZKPUpgradedInner<'a> {
    fn new(base_context: &Base<'a>, batch: DZKPBatch) -> Arc<Self> {
        Arc::new(DZKPUpgradedInner {
            prss: base_context.inner.prss,
            gateway: base_context.inner.gateway,
            batch,
        })
    }
}
