use std::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use async_trait::async_trait;
use ipa_step::{Step, StepNarrow};

use crate::{
    error::Error,
    helpers::{MpcMessage, MpcReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        context::{
            dzkp_validator::{Batch, MaliciousDZKPValidatorInner, Segment},
            prss::InstrumentedIndexedSharedRandomness,
            step::DzkpBatchStep,
            Context as ContextTrait, DZKPContext, InstrumentedSequentialSharedRandomness,
            MaliciousContext,
        },
        Gate, RecordId,
    },
    seq_join::SeqJoin,
    sync::{Arc, Weak},
};

/// Represents protocol context in malicious setting when using zero-knowledge proofs,
/// i.e. secure against one active adversary in 3 party MPC ring.
#[derive(Clone)]
pub struct DZKPUpgraded<'a> {
    validator_inner: Weak<MaliciousDZKPValidatorInner<'a>>,
    base_ctx: MaliciousContext<'a>,
}

impl<'a> DZKPUpgraded<'a> {
    pub(super) fn new(
        validator_inner: &Arc<MaliciousDZKPValidatorInner<'a>>,
        base_ctx: MaliciousContext<'a>,
    ) -> Self {
        Self {
            validator_inner: Arc::downgrade(validator_inner),
            base_ctx,
        }
    }

    pub fn push(&self, record_id: RecordId, segment: Segment) {
        self.with_batch(record_id, |batch| {
            batch.push(self.base_ctx.gate().clone(), record_id, segment);
        });
    }

    fn with_batch<C: FnOnce(&mut Batch) -> T, T>(&self, record_id: RecordId, action: C) -> T {
        let validator_inner = self.validator_inner.upgrade().expect("Validator is active");

        let mut batcher = validator_inner.batcher.lock().unwrap();
        let state = batcher.get_batch(record_id);
        (action)(&mut state.batch)
    }
}

#[async_trait]
impl<'a> DZKPContext for DZKPUpgraded<'a> {
    async fn validate_record(&self, record_id: RecordId) -> Result<(), Error> {
        let validator_inner = self.validator_inner.upgrade().expect("validator is active");

        let ctx = validator_inner.validate_ctx.clone();

        let validation_future = validator_inner
            .batcher
            .lock()
            .unwrap()
            .validate_record(record_id, |batch_idx, batch| {
                batch.validate(ctx.narrow(&DzkpBatchStep(batch_idx)))
            });

        validation_future.await
    }
}

impl<'a> super::Context for DZKPUpgraded<'a> {
    fn role(&self) -> Role {
        self.base_ctx.role()
    }

    fn gate(&self) -> &Gate {
        self.base_ctx.gate()
    }

    fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self
    where
        Gate: StepNarrow<S>,
    {
        Self {
            base_ctx: self.base_ctx.narrow(step),
            ..self.clone()
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            base_ctx: self.base_ctx.set_total_records(total_records),
            ..self.clone()
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.base_ctx.total_records()
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        self.base_ctx.prss()
    }

    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
    ) {
        self.base_ctx.prss_rng()
    }

    fn send_channel<M: MpcMessage>(&self, role: Role) -> SendingEnd<Role, M> {
        self.base_ctx.send_channel(role)
    }

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.base_ctx.recv_channel(role)
    }
}

impl<'a> SeqJoin for DZKPUpgraded<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.base_ctx.active_work()
    }
}

impl Debug for DZKPUpgraded<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "DZKPMaliciousContext")
    }
}
