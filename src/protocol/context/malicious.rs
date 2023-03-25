use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    iter::{repeat, zip},
    marker::PhantomData,
};

use crate::seq_join::seq_try_join_all;
use async_trait::async_trait;
use futures::future::{try_join, try_join3, try_join_all};

use crate::{
    error::Error,
    ff::Field,
    helpers::{ChannelId, Gateway, Message, ReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        attribution::input::MCCappedCreditsWithAggregationBit,
        basics::{
            mul::malicious::Step::RandomnessForValidation, SecureMul, ShareKnownValue,
            ZeroPositions,
        },
        context::{
            prss::InstrumentedIndexedSharedRandomness, Context,
            InstrumentedSequentialSharedRandomness, SemiHonestContext,
        },
        malicious::MaliciousValidatorAccumulator,
        modulus_conversion::BitConversionTriple,
        prss::Endpoint as PrssEndpoint,
        BitOpStep, NoRecord, RecordBinding, RecordId, Step, Substep,
    },
    repeat64str,
    secret_sharing::{
        replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        Linear as LinearSecretSharing,
    },
    sync::Arc,
};

/// This step is not used at the same place.
/// Upgrades all use this step to distinguish protocol steps from the step that is used to upgrade inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UpgradeStep;

impl crate::protocol::Substep for UpgradeStep {}

impl AsRef<str> for UpgradeStep {
    fn as_ref(&self) -> &str {
        "upgrade"
    }
}

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone)]
pub struct MaliciousContext<'a, F: Field + ExtendableField> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<ContextInner<'a, F>>,
    step: Step,
    total_records: TotalRecords,
}

pub trait SpecialAccessToMaliciousContext<'a, F: Field + ExtendableField> {
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>);
    fn semi_honest_context(self) -> SemiHonestContext<'a>;
}

impl<'a, F: Field + ExtendableField> MaliciousContext<'a, F> {
    pub(super) fn new<S: Substep + ?Sized>(
        source: &SemiHonestContext<'a>,
        malicious_step: &S,
        acc: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> Self {
        Self {
            inner: ContextInner::new(source, acc, r_share),
            step: source.step().narrow(malicious_step),
            total_records: TotalRecords::Unspecified,
        }
    }

    /// TODO: This is not fast, but we can't just `reinterpret_cast` here.
    fn as_semi_honest(&self) -> SemiHonestContext<'a> {
        SemiHonestContext::new_complete(
            self.inner.prss,
            self.inner.gateway,
            self.step.clone(),
            self.total_records,
        )
    }

    async fn upgrade_one(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        //
        // This code is drawn from:
        // "Field Extension in Secret-Shared Form and Its Applications to Efficient Secure Computation"
        // R. Kikuchi, N. Attrapadung, K. Hamada, D. Ikarashi, A. Ishida, T. Matsuda, Y. Sakai, and J. C. N. Schuldt
        // <https://eprint.iacr.org/2019/386.pdf>
        //
        // See protocol 4.15
        // In Step 3: "Randomization of inputs:", it says:
        //
        // For each input wire sharing `[v_j]` (where j ∈ {1, . . . , M}), the parties locally
        // compute the induced share `[[v_j]] = f([v_j], 0, . . . , 0)`.
        // Then, the parties call `Ḟ_mult` on `[[ȓ]]` and `[[v_j]]` to receive `[[ȓ · v_j]]`
        //
        let induced_share = Replicated::new(x.left().to_extended(), x.right().to_extended());

        let rx = induced_share
            .multiply_sparse(
                &self.inner.r_share,
                self.as_semi_honest(),
                record_id,
                (zeros_at, ZeroPositions::Pvvv),
            )
            .await?;
        let m = MaliciousReplicated::new(x, rx);
        let narrowed = self.narrow(&RandomnessForValidation);
        let prss = narrowed.prss();
        self.inner.accumulator.accumulate_macs(&prss, record_id, &m);
        Ok(m)
    }

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F>: UpgradeToMalicious<T, M>,
    {
        UpgradeContext {
            ctx: self.narrow(&UpgradeStep),
            record_binding: NoRecord,
        }
        .upgrade(input)
        .await
    }

    /// Upgrade a sparse input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    #[cfg(test)]
    pub async fn upgrade_sparse(
        &self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        UpgradeContext {
            ctx: self.narrow(&UpgradeStep),
            record_binding: NoRecord,
        }
        .upgrade_sparse(input, zeros_at)
        .await
    }

    /// Upgrade an input for a specific bit index and record using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    pub async fn upgrade_for<T, M>(&self, record_id: RecordId, input: T) -> Result<M, Error>
    where
        for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
    {
        UpgradeContext {
            ctx: self.narrow(&UpgradeStep),
            record_binding: record_id,
        }
        .upgrade(input)
        .await
    }

    pub fn share_known_value(&self, value: F) -> MaliciousReplicated<F> {
        MaliciousReplicated::new(
            Replicated::share_known_value(&self.clone().semi_honest_context(), value),
            self.inner.r_share.clone() * value.to_extended(),
        )
    }
}

impl<'a, F: Field + ExtendableField> Context for MaliciousContext<'a, F> {
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

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            step: self.step.clone(),
            total_records: self.total_records.overwrite(total_records),
        }
    }

    fn is_last_record<T: Into<RecordId>>(&self, record_id: T) -> bool {
        self.total_records.is_last(record_id)
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

    fn send_channel<M: Message>(&self, role: Role) -> SendingEnd<M> {
        self.inner
            .gateway
            .get_sender(&ChannelId::new(role, self.step.clone()), self.total_records)
    }

    fn recv_channel<M: Message>(&self, role: Role) -> ReceivingEnd<M> {
        self.inner
            .gateway
            .get_receiver(&ChannelId::new(role, self.step.clone()))
    }
}

/// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
/// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
/// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
/// this implementation makes it easier to reinterpret the context as semi-honest.
impl<'a, F: Field + ExtendableField> SpecialAccessToMaliciousContext<'a, F>
    for MaliciousContext<'a, F>
{
    fn accumulate_macs(self, record_id: RecordId, x: &MaliciousReplicated<F>) {
        self.inner
            .accumulator
            .accumulate_macs(&self.prss(), record_id, x);
    }

    /// Get a semi-honest context that is an  exact copy of this malicious
    /// context, so it will be tied up to the same step and prss.
    #[must_use]
    fn semi_honest_context(self) -> SemiHonestContext<'a> {
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

impl<F: Field + ExtendableField> Debug for MaliciousContext<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext<{:?}>", type_name::<F>())
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
    V1,
    V2,
}

impl crate::protocol::Substep for UpgradeModConvStep {}

impl AsRef<str> for UpgradeModConvStep {
    fn as_ref(&self) -> &str {
        match self {
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
impl<'a, F: Field + ExtendableField>
    UpgradeToMalicious<
        IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
        IPAModulusConvertedInputRowWrapper<F, MaliciousReplicated<F>>,
    > for UpgradeContext<'a, F, RecordId>
{
    async fn upgrade(
        self,
        input: IPAModulusConvertedInputRowWrapper<F, Replicated<F>>,
    ) -> Result<IPAModulusConvertedInputRowWrapper<F, MaliciousReplicated<F>>, Error> {
        let (is_trigger_bit, trigger_value) = try_join(
            self.ctx.narrow(&UpgradeModConvStep::V1).upgrade_one(
                self.record_binding,
                input.is_trigger_bit,
                ZeroPositions::Pvvv,
            ),
            self.ctx.narrow(&UpgradeModConvStep::V2).upgrade_one(
                self.record_binding,
                input.trigger_value,
                ZeroPositions::Pvvv,
            ),
        )
        .await?;

        Ok(IPAModulusConvertedInputRowWrapper::new(
            is_trigger_bit,
            trigger_value,
        ))
    }
}

pub struct IPAModulusConvertedInputRowWrapper<F: Field, T: LinearSecretSharing<F>> {
    pub is_trigger_bit: T,
    pub trigger_value: T,
    _marker: PhantomData<F>,
}

impl<F: Field, T: LinearSecretSharing<F>> IPAModulusConvertedInputRowWrapper<F, T> {
    pub fn new(is_trigger_bit: T, trigger_value: T) -> Self {
        Self {
            is_trigger_bit,
            trigger_value,
            _marker: PhantomData,
        }
    }
}

#[async_trait]
impl<'a, F: Field + ExtendableField>
    UpgradeToMalicious<
        MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
        MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>,
    > for UpgradeContext<'a, F, RecordId>
{
    async fn upgrade(
        self,
        input: MCCappedCreditsWithAggregationBit<F, Replicated<F>>,
    ) -> Result<MCCappedCreditsWithAggregationBit<F, MaliciousReplicated<F>>, Error> {
        let ctx_ref = &self.ctx;
        let breakdown_key = try_join_all(input.breakdown_key.into_iter().enumerate().map(
            |(idx, bit)| async move {
                ctx_ref
                    .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V0(idx))
                    .upgrade_one(self.record_binding, bit, ZeroPositions::Pvvv)
                    .await
            },
        ))
        .await?;

        let helper_bit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V1)
            .upgrade_one(self.record_binding, input.helper_bit, ZeroPositions::Pvvv)
            .await?;

        let aggregation_bit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V2)
            .upgrade_one(
                self.record_binding,
                input.aggregation_bit,
                ZeroPositions::Pvvv,
            )
            .await?;

        let credit = self
            .ctx
            .narrow(&UpgradeMCCappedCreditsWithAggregationBit::V3)
            .upgrade_one(self.record_binding, input.credit, ZeroPositions::Pvvv)
            .await?;
        Ok(MCCappedCreditsWithAggregationBit::new(
            helper_bit,
            aggregation_bit,
            breakdown_key,
            credit,
        ))
    }
}

struct ContextInner<'a, F: Field + ExtendableField> {
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    accumulator: MaliciousValidatorAccumulator<F>,
    r_share: Replicated<F::ExtendedField>,
}

impl<'a, F: Field + ExtendableField> ContextInner<'a, F> {
    fn new(
        semi_honest: &SemiHonestContext<'a>,
        accumulator: MaliciousValidatorAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> Arc<Self> {
        Arc::new(ContextInner {
            prss: semi_honest.inner.prss,
            gateway: semi_honest.inner.gateway,
            accumulator,
            r_share,
        })
    }
}

/// Special context type used for malicious upgrades.
///
/// The `B: RecordBinding` type parameter is used to prevent using the record ID multiple times to
/// implement an upgrade. For example, trying to use the record ID to iterate over both the inner
/// and outer vectors in a `Vec<Vec<T>>` is an error. Instead, one level of iteration can use the
/// record ID and the other can use something like a `BitOpStep`.
///
/// ```no_run
/// use raw_ipa::protocol::{context::{UpgradeContext, UpgradeToMalicious}, NoRecord, RecordId};
/// use raw_ipa::ff::Fp32BitPrime;
/// use raw_ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// // Note: Unbound upgrades only work when testing.
/// #[cfg(test)]
/// let _ = <UpgradeContext<Fp32BitPrime, NoRecord> as UpgradeToMalicious<Replicated<Fp32BitPrime>, _>>::upgrade;
/// let _ = <UpgradeContext<Fp32BitPrime, RecordId> as UpgradeToMalicious<Replicated<Fp32BitPrime>, _>>::upgrade;
/// #[cfg(test)]
/// let _ = <UpgradeContext<Fp32BitPrime, NoRecord> as UpgradeToMalicious<(Replicated<Fp32BitPrime>, Replicated<Fp32BitPrime>), _>>::upgrade;
/// let _ = <UpgradeContext<Fp32BitPrime, NoRecord> as UpgradeToMalicious<Vec<Replicated<Fp32BitPrime>>, _>>::upgrade;
/// let _ = <UpgradeContext<Fp32BitPrime, NoRecord> as UpgradeToMalicious<(Vec<Replicated<Fp32BitPrime>>, Vec<Replicated<Fp32BitPrime>>), _>>::upgrade;
/// ```
///
/// ```compile_fail
/// use raw_ipa::protocol::{context::{UpgradeContext, UpgradeToMalicious}, NoRecord, RecordId};
/// use raw_ipa::ff::Fp32BitPrime;
/// use raw_ipa::secret_sharing::replicated::{
///     malicious::AdditiveShare as MaliciousReplicated, semi_honest::AdditiveShare as Replicated,
/// };
/// // This can't be upgraded with a record-bound context because the record ID
/// // is used internally for vector indexing.
/// let _ = <UpgradeContext<Fp32BitPrime, RecordId> as UpgradeToMalicious<Vec<Replicated<Fp32BitPrime>>, _>>::upgrade;
/// ```
pub struct UpgradeContext<'a, F: Field + ExtendableField, B: RecordBinding = NoRecord> {
    ctx: MaliciousContext<'a, F>,
    record_binding: B,
}

impl<'a, F: Field + ExtendableField, B: RecordBinding> UpgradeContext<'a, F, B> {
    fn narrow<SS: Substep>(&self, step: &SS) -> Self {
        Self {
            ctx: self.ctx.narrow(step),
            record_binding: self.record_binding,
        }
    }
}

#[async_trait]
pub trait UpgradeToMalicious<T, M> {
    async fn upgrade(self, input: T) -> Result<M, Error>;
}

#[async_trait]
impl<'a, F: Field + ExtendableField>
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
        let (t0, t1, t2) = try_join3(
            self.ctx.narrow(&UpgradeTripleStep::V0).upgrade_one(
                self.record_binding,
                v0,
                ZeroPositions::Pvzz,
            ),
            self.ctx.narrow(&UpgradeTripleStep::V1).upgrade_one(
                self.record_binding,
                v1,
                ZeroPositions::Pzvz,
            ),
            self.ctx.narrow(&UpgradeTripleStep::V2).upgrade_one(
                self.record_binding,
                v2,
                ZeroPositions::Pzzv,
            ),
        )
        .await?;
        Ok(BitConversionTriple([t0, t1, t2]))
    }
}

#[async_trait]
impl<F: Field + ExtendableField> UpgradeToMalicious<(), ()> for UpgradeContext<'_, F, NoRecord> {
    async fn upgrade(self, _input: ()) -> Result<(), Error> {
        Ok(())
    }
}

#[async_trait]
impl<'a, F, T, TM, U, UM> UpgradeToMalicious<(T, U), (TM, UM)> for UpgradeContext<'a, F, NoRecord>
where
    F: Field + ExtendableField,
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
    F: Field + ExtendableField,
    T: Send + 'static,
    M: Send + 'static,
    for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
{
    async fn upgrade(self, input: Vec<T>) -> Result<Vec<M>, Error> {
        let ctx = self.ctx.set_total_records(input.len());
        let ctx_ref = &ctx;
        seq_try_join_all(input.into_iter().enumerate().map(|(i, share)| async move {
            // TODO: make it a bit more ergonomic to call with record id bound
            UpgradeContext {
                ctx: ctx_ref.clone(),
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
    F: Field + ExtendableField,
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
        let ctx = self.ctx.set_total_records(num_records);
        let all_ctx = (0..num_columns).map(|idx| ctx.narrow(&Upgrade2DVectors::V(idx)));

        seq_try_join_all(zip(repeat(all_ctx), input.into_iter()).enumerate().map(
            |(record_idx, (all_ctx, one_input))| async move {
                // This inner join is truly concurrent.
                try_join_all(zip(all_ctx, one_input).map(|(ctx, share)| async move {
                    UpgradeContext {
                        ctx,
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
    F: Field + ExtendableField,
{
    async fn upgrade(self, input: Replicated<F>) -> Result<MaliciousReplicated<F>, Error> {
        self.ctx
            .upgrade_one(self.record_binding, input, ZeroPositions::Pvvv)
            .await
    }
}

// Impl for upgrading things that can be upgraded using a single record ID using a non-record-bound
// context. This is only used for tests where the protocol takes a single `Replicated<F>` input.
#[cfg(test)]
#[async_trait]
impl<'a, F, T, M> UpgradeToMalicious<T, M> for UpgradeContext<'a, F, NoRecord>
where
    F: Field + ExtendableField,
    T: Send + 'static,
    for<'u> UpgradeContext<'u, F, RecordId>: UpgradeToMalicious<T, M>,
{
    async fn upgrade(self, input: T) -> Result<M, Error> {
        let ctx = if self.ctx.total_records.is_unspecified() {
            self.ctx.set_total_records(1)
        } else {
            self.ctx
        };
        UpgradeContext {
            ctx,
            record_binding: crate::protocol::RECORD_0,
        }
        .upgrade(input)
        .await
    }
}

// This could also work on a record-bound context, but it's only used in one place for tests where
// that's not currently required.
#[cfg(test)]
impl<'a, F: Field + ExtendableField> UpgradeContext<'a, F, NoRecord> {
    async fn upgrade_sparse(
        self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<MaliciousReplicated<F>, Error> {
        self.ctx
            .upgrade_one(RecordId::from(0u32), input, zeros_at)
            .await
    }
}
