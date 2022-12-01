use futures::future::try_join_all;

use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::context::{Context, SemiHonestContext};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::modulus_conversion::BitConversionTriple;
use crate::protocol::mul::ZeroPositions;
use crate::protocol::mul::{malicious::Step::RandomnessForValidation, SecureMul};
use crate::protocol::prss::{
    Endpoint as PrssEndpoint, IndexedSharedRandomness, SequentialSharedRandomness,
};
use crate::protocol::{BitOpStep, RecordId, Step, Substep};
use crate::secret_sharing::{MaliciousReplicated, Replicated};
use crate::sync::Arc;

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
        self.upgrade_sparse(record_id, input, ZeroPositions::Pvvv)
            .await
    }

    pub async fn upgrade_sparse(
        &self,
        record_id: RecordId,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner.upgrade(record_id, input, zeros_at).await
    }

    /// Upgrade an input for a specific bit index using this context.  Use this for
    /// inputs that have multiple bit positions in place of `upgrade()`.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_bit(
        &self,
        record_id: RecordId,
        bit_index: u32,
        input: Replicated<F>,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner
            .upgrade_bit(record_id, bit_index, input, ZeroPositions::Pvvv)
            .await
    }

    /// Upgrade an bit conversion triple for a specific bit.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_bit_triple(
        &self,
        record_id: RecordId,
        triple: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<MaliciousReplicated<F>>, Error> {
        self.inner.upgrade_bit_triple(record_id, triple).await
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

enum UpgradeTripleStep {
    V0,
    V1,
    V2,
}

impl crate::protocol::Substep for UpgradeTripleStep {}

impl AsRef<str> for UpgradeTripleStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::V0 => "upgrade_bit_triple0",
            Self::V1 => "upgrade_bit_triple1",
            Self::V2 => "upgrade_bit_triple2",
        }
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

    async fn upgrade_one(
        &self,
        ctx: SemiHonestContext<'a, F>,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        let prss = ctx.narrow(&RandomnessForValidation).prss();
        let rx = ctx
            .multiply_sparse(
                record_id,
                &x,
                &self.r_share,
                &(zeros_at, ZeroPositions::Pvvv),
            )
            .await?;
        let m = MaliciousReplicated::new(x, rx);
        self.accumulator.accumulate_macs(&prss, record_id, &m);
        Ok(m)
    }

    async fn upgrade(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_one(self.upgrade_ctx.clone(), record_id, x, zeros_at)
            .await
    }

    async fn upgrade_bit(
        &self,
        record_id: RecordId,
        bit_index: u32,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.upgrade_one(
            self.upgrade_ctx.narrow(&BitOpStep::from(bit_index)),
            record_id,
            x,
            zeros_at,
        )
        .await
    }

    async fn upgrade_bit_triple(
        &self,
        record_id: RecordId,
        triple: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<MaliciousReplicated<F>>, Error> {
        let [v0, v1, v2] = triple.0;
        Ok(BitConversionTriple(
            try_join_all([
                self.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V0),
                    record_id,
                    v0,
                    ZeroPositions::Pvzz,
                ),
                self.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V1),
                    record_id,
                    v1,
                    ZeroPositions::Pzvz,
                ),
                self.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V2),
                    record_id,
                    v2,
                    ZeroPositions::Pzzv,
                ),
            ])
            .await?
            .try_into()
            .unwrap(),
        ))
    }
}
