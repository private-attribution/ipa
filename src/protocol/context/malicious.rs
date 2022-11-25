use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::mul::SecureMul;
use crate::protocol::prss::{
    Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness,
};
use crate::protocol::{RecordId, Step, Substep};
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use std::sync::Arc;

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<ContextInner<'a, F>>,
    step: Step,
}

pub trait SpecialAccessToMaliciousContext<'a, F: Field> {
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>);
    fn semi_honest_context(self) -> SemiHonestContext<'a, F>;
}

impl<'a, F: Field> MaliciousContext<'a, F> {
    pub(super) fn new<S: Substep + ?Sized>(
        source: &SemiHonestContext<'a, F>,
        malicious_step: &S,
        upgrade_ctx: SemiHonestContext<'a, F>,
        acc: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Self {
        Self {
            inner: ContextInner::new(upgrade_ctx, acc, r_share),
            step: source.step().narrow(malicious_step),
        }
    }

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade(
        &self,
        record_id: RecordId,
        input: Replicated<F>,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner.upgrade(record_id, input).await
    }
}

impl<'a, F: Field> Context<F> for MaliciousContext<'a, F> {
    type Share = MaliciousReplicated<F>;

    fn role(&self) -> Role {
        self.inner.role
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.narrow(step),
        }
    }

    fn prss(&self) -> Arc<IndexedSharedRandomness> {
        self.inner.prss.indexed(self.step())
    }

    fn prss_rng(&self) -> (SequentialSharedRandomness, SequentialSharedRandomness) {
        self.inner.prss.sequential(self.step())
    }

    fn mesh(&self) -> Mesh<'_, '_> {
        self.inner.gateway.mesh(self.step())
    }

    fn share_of_one(&self) -> <Self as Context<F>>::Share {
        MaliciousReplicated::one(self.role(), self.inner.r_share.clone())
    }
}

/// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
/// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
/// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
/// this implementation makes it easier to reinterpret the context as semi-honest.
impl<'a, F: Field> SpecialAccessToMaliciousContext<'a, F> for MaliciousContext<'a, F> {
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>) {
        self.inner
            .accumulator
            .accumulate_macs(&self.prss(), record_id, x);
    }

    /// Get a semi-honest context that is an  exact copy of this malicious
    /// context, so it will be tied up to the same step and prss.
    #[must_use]
    fn semi_honest_context(self) -> SemiHonestContext<'a, F> {
        // TODO: it can be made more efficient by impersonating malicious context as semi-honest
        // it does not work as of today because of https://github.com/rust-lang/rust/issues/20400
        // while it is possible to define a struct that wraps a reference to malicious context
        // and implement `Context` trait for it, implementing SecureMul and Reveal for Context
        // is not
        // For the same reason, it is not possible to implement Context<F, Share = Replicated<F>>
        // for `MaliciousContext`. Deep clone is the only option
        let mut ctx = SemiHonestContext::new(self.inner.role, self.inner.prss, self.inner.gateway);
        ctx.step = self.step;

        ctx
    }
}

#[derive(Debug)]
struct ContextInner<'a, F: Field> {
    role: Role,
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    upgrade_ctx: SemiHonestContext<'a, F>,
    accumulator: MaliciousValidatorAccumulator<F>,
    r_share: Replicated<F>,
}

impl<'a, F: Field> ContextInner<'a, F> {
    fn new(
        upgrade_ctx: SemiHonestContext<'a, F>,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F>,
    ) -> Arc<Self> {
        Arc::new(ContextInner {
            role: upgrade_ctx.inner.role,
            prss: upgrade_ctx.inner.prss,
            gateway: upgrade_ctx.inner.gateway,
            upgrade_ctx,
            accumulator,
            r_share,
        })
    }

    async fn upgrade(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
    ) -> Result<MaliciousReplicated<F>, Error> {
        let rx = self
            .upgrade_ctx
            .clone()
            .multiply(record_id, &x, &self.r_share)
            .await?;
        Ok(MaliciousReplicated::new(x, rx))
    }
}
