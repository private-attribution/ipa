use std::iter::{repeat, zip};
use std::marker::PhantomData;

use async_trait::async_trait;
use futures::future::{try_join, try_join_all};

use crate::error::Error;
use crate::ff::Field;
use crate::helpers::messaging::{Gateway, Mesh, TotalRecords};
use crate::helpers::Role;
use crate::protocol::attribution::input::MCCappedCreditsWithAggregationBit;
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
use crate::repeat64str;
use crate::secret_sharing::replicated::{
    malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
};
use crate::secret_sharing::Arithmetic;
use crate::sync::Arc;

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone, Debug)]
pub struct MaliciousContext<'a, F: Field> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<ContextInner<'a, F>>,
    step: Step,
    total_records: TotalRecords,
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
            total_records: TotalRecords::Unspecified,
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
        self.inner.gateway.role()
    }

    fn step(&self) -> &Step {
        &self.step
    }

    fn narrow<S: Substep + ?Sized>(&self, step: &S) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.narrow(step),
            total_records: self.total_records,
        }
    }

    fn is_total_records_unspecified(&self) -> bool {
        self.total_records.is_unspecified()
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        debug_assert!(
            self.is_total_records_unspecified(),
            "attempt to set total_records more than once"
        );
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: total_records.into(),
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
        self.inner.gateway.mesh(self.step(), self.total_records)
    }

    fn share_known_value(&self, value: F) -> <Self as Context<F>>::Share {
        MaliciousReplicated::share_known_value(self.role(), value, self.inner.r_share.clone())
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
        let mut ctx = SemiHonestContext::new_with_total_records(
            self.inner.prss,
            self.inner.gateway,
            self.total_records,
        );
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

enum UpgradeModConvStep {
    V0(usize),
    V1,
    V2,
}

impl crate::protocol::Substep for UpgradeModConvStep {}

impl AsRef<str> for UpgradeModConvStep {
    fn as_ref(&self) -> &str {
        const UPGRADE_MOD_CONV0: [&str; 64] = repeat64str!["upgrade_mod_conv0"];

        match self {
            Self::V0(i) => UPGRADE_MOD_CONV0[*i],
            Self::V1 => "upgrade_mod_conv1",
            Self::V2 => "upgrade_mod_conv2",
        }
    }
}

enum UpgradeMCCappedCreditsWithAggregationBit {
    V0(usize),
    V1,
    V2,
    V3,
}

impl crate::protocol::Substep for UpgradeMCCappedCreditsWithAggregationBit {}

impl AsRef<str> for UpgradeMCCappedCreditsWithAggregationBit {
    fn as_ref(&self) -> &str {
        const UPGRADE_AGGREGATION_BIT0: [&str; 64] = repeat64str!["upgrade_aggregation_bit0"];

        match self {
            Self::V0(i) => UPGRADE_AGGREGATION_BIT0[*i],
            Self::V1 => "upgrade_aggregation_bit1",
            Self::V2 => "upgrade_aggregation_bit2",
            Self::V3 => "upgrade_aggregation_bit3",
        }
    }
}

#[async_trait]
impl<'a, F: Field>
    UpgradeToMalicious<
        IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
        IPAModulusConvertedInputRowWrapper<F, MaliciousReplicated<F>>,
    > for UpgradeContext<'a, F, RecordId>
{
    async fn upgrade(
        self,
        input: IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
    ) -> Result<IPAModulusConvertedInputRowWrapper<F, MaliciousReplicated<F>>, Error> {
        let ctx_ref = &self.upgrade_ctx;
        let mk_shares = try_join_all(input.mk_shares.into_iter().enumerate().map(
            |(idx, mk_share)| async move {
                self.inner
                    .upgrade_one(
                        ctx_ref.narrow(&UpgradeModConvStep::V0(idx)),
                        self.record_binding,
                        mk_share,
                        ZeroPositions::Pvvv,
                    )
                    .await
            },
        ))
        .await?;

        let is_trigger_bit = self
            .inner
            .upgrade_one(
                self.upgrade_ctx.narrow(&UpgradeModConvStep::V1),
                self.record_binding,
                input.is_trigger_bit,
                ZeroPositions::Pvvv,
            )
            .await?;

        let trigger_value = self
            .inner
            .upgrade_one(
                self.upgrade_ctx.narrow(&UpgradeModConvStep::V2),
                self.record_binding,
                input.trigger_value,
                ZeroPositions::Pvvv,
            )
            .await?;
        Ok(IPAModulusConvertedInputRowWrapper {
            mk_shares,
            is_trigger_bit,
            trigger_value,
            _marker: PhantomData,
        })
    }
}

pub struct IPAModulusConvertedInputRowWrapper<F: Field, T: Arithmetic<F>> {
    pub mk_shares: Vec<T>,
    pub is_trigger_bit: T,
    pub trigger_value: T,
    pub _marker: PhantomData<F>,
}

#[async_trait]
impl<'a, F: Field>
    UpgradeToMalicious<
        MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
        MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>,
    > for UpgradeContext<'a, F, RecordId>
{
    async fn upgrade(
        self,
        input: MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
    ) -> Result<MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>, Error> {
        let ctx_ref = &self.upgrade_ctx;
        let breakdown_key = try_join_all(input.breakdown_key.into_iter().enumerate().map(
            |(idx, bit)| async move {
                self.inner
                    .upgrade_one(
                        ctx_ref.narrow(&UpgradeMCCappedCreditsWithAggregationBit::V0(idx)),
                        self.record_binding,
                        bit,
                        ZeroPositions::Pvvv,
                    )
                    .await
            },
        ))
        .await?;

        let helper_bit = self
            .inner
            .upgrade_one(
                self.upgrade_ctx
                    .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V1),
                self.record_binding,
                input.helper_bit,
                ZeroPositions::Pvvv,
            )
            .await?;

        let aggregation_bit = self
            .inner
            .upgrade_one(
                self.upgrade_ctx
                    .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V2),
                self.record_binding,
                input.aggregation_bit,
                ZeroPositions::Pvvv,
            )
            .await?;

        let credit = self
            .inner
            .upgrade_one(
                self.upgrade_ctx
                    .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V3),
                self.record_binding,
                input.credit,
                ZeroPositions::Pvvv,
            )
            .await?;
        Ok(MCCappedCreditsWithAggregationBit {
            helper_bit,
            aggregation_bit,
            breakdown_key,
            credit,
            _marker: PhantomData,
        })
    }
}

#[derive(Debug)]
struct ContextInner<'a, F: Field> {
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
        // TODO: This function is called from within solved_bits, where the
        // total number of records is indeterminate.  If using it elsewhere,
        // need to update this. (However the concept of indeterminate total
        // records probably needs to go away.)
        UpgradeContext {
            upgrade_ctx: self
                .upgrade_ctx
                .set_total_records(TotalRecords::Indeterminate)
                .narrow(step),
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
                self.upgrade_ctx.set_total_records(1),
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

enum Upgrade2DVectors {
    V(usize),
}
impl crate::protocol::Substep for Upgrade2DVectors {}

impl AsRef<str> for Upgrade2DVectors {
    fn as_ref(&self) -> &str {
        const COLUMN: [&str; 64] = repeat64str!["upgrade_2d"];

        match self {
            Self::V(i) => COLUMN[*i],
        }
    }
}

#[async_trait]
impl<F, T, M> UpgradeToMalicious<Vec<T>, Vec<M>> for UpgradeContext<'_, F, NoRecord>
where
    F: Field,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
{
    async fn upgrade(self, input: Vec<T>) -> Result<Vec<M>, Error> {
        let ctx = self.upgrade_ctx.set_total_records(input.len());
        let ctx_ref = &ctx;
        try_join_all(input.into_iter().enumerate().map(|(i, share)| async move {
            // TODO: make it a bit more ergonomic to call with record id bound
            UpgradeContext {
                upgrade_ctx: ctx_ref.clone(),
                inner: self.inner,
                record_binding: RecordId::from(i),
            }
            .upgrade(share)
            .await
        }))
        .await
    }
}

/// This function is not a generic implementation of 2D vector upgrade.
/// It assumes the inner vector is much smaller (e.g. multiple bits per record) than the outer vector (e.g. records)
/// Each inner vector element uses a different context and outer vector shares a context for the same inner vector index
#[async_trait]
impl<'a, F, T, M> UpgradeToMalicious<Vec<Vec<T>>, Vec<Vec<M>>> for UpgradeContext<'a, F, NoRecord>
where
    F: Field,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
{
    /// # Panics
    /// Panics if input is empty
    async fn upgrade(self, input: Vec<Vec<T>>) -> Result<Vec<Vec<M>>, Error> {
        let num_records = input.len();
        assert_ne!(num_records, 0);
        let num_columns = input[0].len();
        let ctx = self.upgrade_ctx.set_total_records(num_records);
        let all_ctx = (0..num_columns).map(|idx| ctx.narrow(&Upgrade2DVectors::V(idx)));

        try_join_all(zip(repeat(all_ctx), input.into_iter()).enumerate().map(
            |(record_idx, (all_ctx, one_input))| async move {
                try_join_all(zip(all_ctx, one_input).map(|(ctx, share)| async move {
                    UpgradeContext {
                        upgrade_ctx: ctx,
                        inner: self.inner,
                        record_binding: RecordId::from(record_idx),
                    }
                    .upgrade(share)
                    .await
                }))
                .await
            },
        ))
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
            upgrade_ctx: self.upgrade_ctx.set_total_records(1),
            inner: self.inner,
            record_binding: RECORD_0,
        }
        .upgrade(input)
        .await
    }
}
