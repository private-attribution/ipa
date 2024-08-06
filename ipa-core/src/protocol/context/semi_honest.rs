use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    num::NonZeroUsize,
};

use async_trait::async_trait;
use ipa_step::{Step, StepNarrow};

use crate::{
    error::Error,
    helpers::{
        Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd, ShardReceivingEnd,
        TotalRecords,
    },
    protocol::{
        context::{
            dzkp_validator::SemiHonestDZKPValidator, validator::SemiHonest as Validator, Base,
            InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness,
            ShardedContext, SpecialAccessToUpgradedContext, UpgradableContext, UpgradedContext,
        },
        prss::Endpoint as PrssEndpoint,
        Gate, RecordId,
    },
    secret_sharing::replicated::{
        malicious::ExtendableField, semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
    sharding::{NotSharded, ShardBinding, ShardConfiguration, ShardIndex, Sharded},
};

#[derive(Clone)]
pub struct Context<'a, B: ShardBinding> {
    inner: Base<'a, B>,
}
impl ShardConfiguration for Context<'_, Sharded> {
    fn shard_id(&self) -> ShardIndex {
        self.inner.shard_id()
    }

    fn shard_count(&self) -> ShardIndex {
        self.inner.shard_count()
    }
}

impl<'a, B: ShardBinding> Context<'a, B> {
    pub fn new_complete(participant: &'a PrssEndpoint, gateway: &'a Gateway, shard: B) -> Self {
        Self::new_with_gate(participant, gateway, shard, Gate::default())
    }

    pub fn new_with_gate(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        shard: B,
        gate: Gate,
    ) -> Self {
        Self {
            inner: Base::new_complete(participant, gateway, gate, TotalRecords::Unspecified, shard),
        }
    }
}

impl<'a> Context<'a, NotSharded> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_complete(participant, gateway, NotSharded)
    }
}

impl<'a> Context<'a, Sharded> {
    pub fn new_sharded(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        shard: Sharded,
    ) -> Self {
        Self::new_complete(participant, gateway, shard)
    }
}

impl<'a, B: ShardBinding> Context<'a, B> {
    #[cfg(test)]
    #[must_use]
    pub fn from_base(base: Base<'a, B>) -> Self {
        Self { inner: base }
    }
}

impl ShardedContext for Context<'_, Sharded> {
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M> {
        self.inner.shard_send_channel(dest_shard)
    }

    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M> {
        self.inner.shard_recv_channel(origin)
    }
}

impl<'a, B: ShardBinding> super::Context for Context<'a, B> {
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

    fn send_channel<M: MpcMessage>(&self, role: Role) -> SendingEnd<Role, M> {
        self.inner.send_channel(role)
    }

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.inner.recv_channel(role)
    }
}

impl<'a, B: ShardBinding> UpgradableContext for Context<'a, B> {
    type UpgradedContext<F: ExtendableField> = Upgraded<'a, B, F>;
    type Validator<F: ExtendableField> = Validator<'a, B, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        Self::Validator::new(self.inner)
    }

    type DZKPValidator = SemiHonestDZKPValidator<'a, B>;

    fn dzkp_validator(self, _max_multiplications_per_gate: usize) -> Self::DZKPValidator {
        Self::DZKPValidator::new(self.inner)
    }
}

impl<'a, B: ShardBinding> SeqJoin for Context<'a, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl<B: ShardBinding> Debug for Context<'_, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SemiHonestContext")
            .field("shard", &self.inner.sharding)
            .finish()
    }
}

#[derive(Clone)]
pub struct Upgraded<'a, B: ShardBinding, F: ExtendableField> {
    inner: Base<'a, B>,
    _f: PhantomData<F>,
}

impl<'a, B: ShardBinding, F: ExtendableField> Upgraded<'a, B, F> {
    pub(super) fn new(inner: Base<'a, B>) -> Self {
        Self {
            inner,
            _f: PhantomData,
        }
    }
}

impl<F: ExtendableField> ShardConfiguration for Upgraded<'_, Sharded, F> {
    fn shard_id(&self) -> ShardIndex {
        self.inner.shard_id()
    }

    fn shard_count(&self) -> ShardIndex {
        self.inner.shard_count()
    }
}

impl<F: ExtendableField> ShardedContext for Upgraded<'_, Sharded, F> {
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M> {
        self.inner.shard_send_channel(dest_shard)
    }

    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M> {
        self.inner.shard_recv_channel(origin)
    }
}

impl<'a, B: ShardBinding, F: ExtendableField> super::Context for Upgraded<'a, B, F> {
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

impl<'a, B: ShardBinding, F: ExtendableField> SeqJoin for Upgraded<'a, B, F> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

#[async_trait]
impl<'a, B: ShardBinding, F: ExtendableField> UpgradedContext for Upgraded<'a, B, F> {
    type Field = F;
    type Share = Replicated<F>;

    async fn upgrade_one(
        &self,
        _record_id: RecordId,
        x: Replicated<F>,
    ) -> Result<Self::Share, Error> {
        Ok(x)
    }
}

impl<'a, B: ShardBinding, F: ExtendableField> SpecialAccessToUpgradedContext<F>
    for Upgraded<'a, B, F>
{
    type Base = Base<'a, B>;

    fn base_context(self) -> Self::Base {
        self.inner
    }
}

impl<B: ShardBinding, F: ExtendableField> Debug for Upgraded<'_, B, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SemiHonestContext<{:?}, {:?}>",
            type_name::<B>(),
            type_name::<F>()
        )
    }
}
