use async_trait::async_trait;
use futures::future::{try_join, try_join_all};

use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh};
use crate::helpers::Role;
use crate::protocol::basics::mul::malicious::Step::RandomnessForValidation;
use crate::protocol::basics::{SecureMul, ZeroPositions};
use crate::protocol::context::prss::InstrumentedIndexedSharedRandomness;
use crate::protocol::context::{
    Context, InstrumentedSequentialSharedRandomness, SemiHonestContext,
};
use crate::protocol::malicious::MaliciousValidatorAccumulator;
use crate::protocol::modulus_conversion::BitConversionTriple;
use crate::protocol::prss::Endpoint as PrssEndpoint;
use crate::protocol::{BitOpStep, RecordId, Step, Substep, RECORD_0};
use crate::secret_sharing::replicated::{
    malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
};
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
    pub async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F>: UpgradeToMalicious<T, M>,
    {
        self.inner.upgrade(input).await
    }

    /// Upgrade a sparse input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_with_sparse<SS: Substep>(
        &self,
        step: &SS,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner.upgrade_with_sparse(step, input, zeros_at).await
    }

    /// Upgrade an input for a specific bit index and record using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_for_record_with<SS: Substep, T, M>(
        &self,
        step: &SS,
        record_id: RecordId,
        input: T,
    ) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
    {
        self.inner
            .upgrade_for_record_with(step, record_id, input)
            .await
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

    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
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
        let rx = ctx
            .clone()
            .multiply_sparse(
                record_id,
                &x,
                &self.r_share,
                (zeros_at, ZeroPositions::Pvvv),
            )
            .await?;
        let m = MaliciousReplicated::new(x, rx);
        let ctx = ctx.narrow(&RandomnessForValidation);
        let prss = ctx.prss();
        self.accumulator.accumulate_macs(&prss, record_id, &m);
        Ok(m)
    }

    async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F>: UpgradeToMalicious<T, M>,
    {
        UpgradeContext {
            upgrade_ctx: self.upgrade_ctx.clone(),
            inner: self,
            record_binding: NoRecord,
        }
        .upgrade(input)
        .await
    }

    async fn upgrade_with_sparse<SS: Substep>(
        &self,
        step: &SS,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        UpgradeContext {
            upgrade_ctx: self.upgrade_ctx.narrow(step),
            inner: self,
            record_binding: NoRecord,
        }
        .upgrade_sparse(input, zeros_at)
        .await
    }

    async fn upgrade_for_record_with<SS: Substep, T, M>(
        &self,
        step: &SS,
        record_id: RecordId,
        input: T,
    ) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
    {
        UpgradeContext {
            upgrade_ctx: self.upgrade_ctx.narrow(step),
            inner: self,
            record_binding: record_id,
        }
        .upgrade(input)
        .await
    }
}

/// Helper to prevent using the record ID multiple times to implement an upgrade.
///
/// ```no_run
/// use raw_ipa::protocol::{context::{NoRecord, UpgradeContext, UpgradeToMalicious}, RecordId};
/// use raw_ipa::ff::Fp31;
/// use raw_ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// let _ = <UpgradeContext<Fp31, NoRecord> as UpgradeToMalicious<Replicated<Fp31>, _>>::upgrade;
/// let _ = <UpgradeContext<Fp31, RecordId> as UpgradeToMalicious<Replicated<Fp31>, _>>::upgrade;
/// let _ = <UpgradeContext<Fp31, NoRecord> as UpgradeToMalicious<(Replicated<Fp31>, Replicated<Fp31>), _>>::upgrade;
/// let _ = <UpgradeContext<Fp31, NoRecord> as UpgradeToMalicious<Vec<Replicated<Fp31>>, _>>::upgrade;
/// let _ = <UpgradeContext<Fp31, NoRecord> as UpgradeToMalicious<(Vec<Replicated<Fp31>>, Vec<Replicated<Fp31>>), _>>::upgrade;
/// ```
///
/// ```compile_fail
/// use raw_ipa::protocol::{context::{NoRecord, UpgradeContext, UpgradeToMalicious}, RecordId};
/// use raw_ipa::ff::Fp31;
/// use raw_ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// // This can't be upgraded with a record-bound context because the record ID
/// // is used internally for vector indexing.
/// let _ = <UpgradeContext<Fp31, RecordId> as UpgradeToMalicious<Vec<Replicated<Fp31>>, _>>::upgrade;
/// ```
pub trait RecordBinding: Copy + Send + Sync {}

#[derive(Clone, Copy)]
pub struct NoRecord;
impl RecordBinding for NoRecord {}

impl RecordBinding for RecordId {}

pub struct UpgradeContext<'a, F: Field, B: RecordBinding = NoRecord> {
    upgrade_ctx: SemiHonestContext<'a, F>,
    inner: &'a ContextInner<'a, F>,
    record_binding: B,
}

impl<'a, F: Field, B: RecordBinding> UpgradeContext<'a, F, B> {
    fn narrow<SS: Substep>(&self, step: &SS) -> Self {
        Self {
            upgrade_ctx: self.upgrade_ctx.narrow(step),
            inner: self.inner,
            record_binding: self.record_binding,
        }
    }
}

// This could also work on a record-bound context, but it's only used in one place for tests where
// that's not currently required.
impl<'a, F: Field> UpgradeContext<'a, F, NoRecord> {
    async fn upgrade_sparse(
        self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.inner
            .upgrade_one(
                self.upgrade_ctx, /*.set_total_records(1)*/
                RecordId::from(0u32),
                input,
                zeros_at,
            )
            .await
    }
}

#[async_trait]
pub trait UpgradeToMalicious<T, M> {
    async fn upgrade(self, input: T) -> Result<M, Error>;
}

#[async_trait]
impl<'a, F: Field>
    UpgradeToMalicious<
        BitConversionTriple<Replicated<F>>,
        BitConversionTriple<MaliciousReplicated<F>>,
    > for UpgradeContext<'a, F, RecordId>
{
    async fn upgrade(
        self,
        input: BitConversionTriple<Replicated<F>>,
    ) -> Result<BitConversionTriple<MaliciousReplicated<F>>, Error> {
        let [v0, v1, v2] = input.0;
        Ok(BitConversionTriple(
            try_join_all([
                self.inner.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V0),
                    self.record_binding,
                    v0,
                    ZeroPositions::Pvzz,
                ),
                self.inner.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V1),
                    self.record_binding,
                    v1,
                    ZeroPositions::Pzvz,
                ),
                self.inner.upgrade_one(
                    self.upgrade_ctx.narrow(&UpgradeTripleStep::V2),
                    self.record_binding,
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

#[async_trait]
impl<'a, F, T, TM, U, UM> UpgradeToMalicious<(T, U), (TM, UM)> for UpgradeContext<'a, F, NoRecord>
where
    F: Field,
    T: Send + 'static,
    U: Send + 'static,
    TM: Send + Sized,
    UM: Send + Sized,
    for<'u> UpgradeContext<'u, F, NoRecord>: UpgradeToMalicious<T, TM> + UpgradeToMalicious<U, UM>,
{
    async fn upgrade(self, input: (T, U)) -> Result<(TM, UM), Error> {
        try_join(
            self.narrow(&BitOpStep::from(0)).upgrade(input.0),
            self.narrow(&BitOpStep::from(1)).upgrade(input.1),
        )
        .await
    }
}

#[async_trait]
impl<'a, F> UpgradeToMalicious<Vec<Replicated<F>>, Vec<MaliciousReplicated<F>>>
    for UpgradeContext<'a, F, NoRecord>
where
    F: Field,
{
    async fn upgrade(
        self,
        input: Vec<Replicated<F>>,
    ) -> Result<Vec<MaliciousReplicated<F>>, Error> {
        let ctx = self.upgrade_ctx/*.set_total_records(input.len())*/;
        let ctx_ref = &ctx;
        try_join_all(input.into_iter().enumerate().map(|(i, share)| async move {
            self.inner
                .upgrade_one(
                    ctx_ref.clone(),
                    RecordId::from(i),
                    share,
                    ZeroPositions::Pvvv,
                )
                .await
        }))
        .await
    }
}

#[async_trait]
impl<'a, F> UpgradeToMalicious<Replicated<F>, MaliciousReplicated<F>>
    for UpgradeContext<'a, F, RecordId>
where
    F: Field,
{
    async fn upgrade(self, input: Replicated<F>) -> Result<MaliciousReplicated<F>, Error> {
        self.inner
            .upgrade_one(
                self.upgrade_ctx,
                self.record_binding,
                input,
                ZeroPositions::Pvvv,
            )
            .await
    }
}

// Impl for upgrading things that can be upgraded using a single record ID using a non-record-bound
// context. This gets used e.g. when the protocol takes a single `Replicated<F>` input.
#[async_trait]
impl<'a, F, T, M> UpgradeToMalicious<T, M> for UpgradeContext<'a, F, NoRecord>
where
    F: Field,
    T: Send + 'static,
    for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
{
    async fn upgrade(self, input: T) -> Result<M, Error> {
        UpgradeContext {
            upgrade_ctx: self.upgrade_ctx, /*.set_total_records(1)*/
            inner: self.inner,
            record_binding: RECORD_0,
        }
        .upgrade(input)
        .await
    }
}
