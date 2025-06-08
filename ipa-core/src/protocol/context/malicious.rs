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
        Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd, ShardReceivingEnd,
        TotalRecords,
    },
    protocol::{
        Gate, RecordId,
        basics::mul::{semi_honest_multiply, step::MaliciousMultiplyStep::RandomnessForValidation},
        context::{
            Base, Context as ContextTrait, InstrumentedSequentialSharedRandomness, ShardedContext,
            SpecialAccessToUpgradedContext, UpgradableContext, UpgradedContext,
            batcher::Batcher,
            dzkp_validator::MaliciousDZKPValidator,
            prss::InstrumentedIndexedSharedRandomness,
            step::UpgradeStep,
            upgrade::Upgradable,
            validator::{self, BatchValidator},
        },
        prss::{Endpoint as PrssEndpoint, FromPrss},
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField, ExtendableFieldSimd},
        semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
    sharding::{NotSharded, ShardBinding, ShardConfiguration, ShardIndex, Sharded},
    sync::Arc,
};

pub struct MaliciousProtocolSteps<'a, S: Step + ?Sized> {
    pub protocol: &'a S,
    pub validate: &'a S,
}

#[cfg(all(feature = "in-memory-infra", any(test, feature = "test-fixture")))]
pub const TEST_DZKP_STEPS: MaliciousProtocolSteps<'static, super::step::MaliciousProtocolStep> =
    MaliciousProtocolSteps {
        protocol: &super::step::MaliciousProtocolStep::MaliciousProtocol,
        validate: &super::step::MaliciousProtocolStep::Validate,
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

impl ShardedContext for Context<'_, Sharded> {
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

impl<'a> Context<'a, NotSharded> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_with_gate(participant, gateway, Gate::default(), NotSharded)
    }
}

impl<'a, B: ShardBinding> Context<'a, B> {
    pub fn new_with_gate(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        gate: Gate,
        shard: B,
    ) -> Self {
        Self {
            inner: Base::new_complete(participant, gateway, gate, TotalRecords::Unspecified, shard),
        }
    }

    pub(crate) fn validator_context(self) -> Base<'a, B> {
        // The DZKP validator uses communcation channels internally. We don't want any TotalRecords
        // set by the protocol to apply to those channels.
        Base {
            total_records: TotalRecords::Unspecified,
            ..self.inner
        }
    }

    #[must_use]
    pub fn set_active_work(self, new_active_work: NonZeroU32PowerOfTwo) -> Self {
        Self {
            inner: self.inner.set_active_work(new_active_work),
        }
    }
}

impl<B: ShardBinding> super::Context for Context<'_, B> {
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
    type Validator<F: ExtendableField> = BatchValidator<'a, F, B>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        BatchValidator::new(self)
    }

    type DZKPValidator = MaliciousDZKPValidator<'a, B>;

    fn dzkp_validator<S>(
        self,
        steps: MaliciousProtocolSteps<S>,
        max_multiplications_per_gate: usize,
    ) -> Self::DZKPValidator
    where
        Gate: StepNarrow<S>,
        S: Step + ?Sized,
    {
        MaliciousDZKPValidator::new(self, steps, max_multiplications_per_gate)
    }
}

impl<B: ShardBinding> SeqJoin for Context<'_, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl<B: ShardBinding> Debug for Context<'_, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext")
    }
}

use crate::{
    sync::{Mutex, Weak},
    utils::NonZeroU32PowerOfTwo,
};

pub(super) type MacBatcher<'a, F, B> = Mutex<Batcher<'a, validator::Malicious<'a, F, B>>>;

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone)]
pub struct Upgraded<'a, F: ExtendableField, B: ShardBinding> {
    batch: Weak<MacBatcher<'a, F, B>>,
    base_ctx: Context<'a, B>,
}

impl<'a, F: ExtendableField, B: ShardBinding> Upgraded<'a, F, B> {
    pub(super) fn new(batch: &Arc<MacBatcher<'a, F, B>>, ctx: Context<'a, B>) -> Self {
        // The DZKP malicious context adjusts active_work to match records_per_batch.
        // The MAC validator currently configures the batcher with records_per_batch =
        // active_work. If the latter behavior changes, this code may need to be
        // updated.
        let records_per_batch = batch.lock().unwrap().records_per_batch();
        let active_work = ctx.active_work().get();
        assert_eq!(
            records_per_batch, active_work,
            "Expect MAC validation batch size ({records_per_batch}) to match active work ({active_work})",
        );
        Self {
            batch: Arc::downgrade(batch),
            base_ctx: ctx,
        }
    }

    /// Take a secret sharing and add it to the running MAC that this context maintains (if any).
    pub fn accumulate_macs<const N: usize>(
        self,
        record_id: RecordId,
        share: &MaliciousReplicated<F, N>,
    ) where
        F: ExtendableFieldSimd<N>,
        Replicated<F::ExtendedField, N>: FromPrss,
    {
        self.with_batch(record_id, |v| {
            v.accumulator
                .accumulate_macs(&self.prss(), record_id, share);
        });
    }

    /// `TestWorld` malicious methods require access to r share to perform validation.
    /// This method allows such access only in non-prod code.
    #[cfg(any(test, feature = "test-fixture"))]
    #[must_use]
    pub fn r(&self, record_id: RecordId) -> Replicated<F::ExtendedField> {
        self.r_share(record_id)
    }

    /// It is intentionally not public, allows access to it only from within
    /// this module
    fn r_share(&self, record_id: RecordId) -> Replicated<F::ExtendedField> {
        self.with_batch(record_id, |v| v.r_share().clone())
    }

    fn with_batch<C: FnOnce(&mut validator::Malicious<'a, F, B>) -> T, T>(
        &self,
        record_id: RecordId,
        action: C,
    ) -> T {
        let batcher = self.batch.upgrade().expect("Validator is active");

        let mut batch = batcher.lock().unwrap();
        let state = batch.get_batch(record_id);
        (action)(&mut state.batch)
    }
}

#[async_trait]
impl<F: ExtendableField, B: ShardBinding> UpgradedContext for Upgraded<'_, F, B> {
    type Field = F;

    async fn validate_record(&self, record_id: RecordId) -> Result<(), Error> {
        let validation_future = self
            .batch
            .upgrade()
            .expect("Validation batch is active")
            .lock()
            .unwrap()
            .validate_record(record_id, |_batch_idx, batch| batch.validate());

        validation_future.await
    }
}

impl<F: ExtendableField, B: ShardBinding> super::Context for Upgraded<'_, F, B> {
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

impl<F: ExtendableField, B: ShardBinding> SeqJoin for Upgraded<'_, F, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.base_ctx.active_work()
    }
}

/// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
/// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
/// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
/// this implementation makes it easier to reinterpret the context as semi-honest.
impl<'a, F: ExtendableField, B: ShardBinding> SpecialAccessToUpgradedContext<F>
    for Upgraded<'a, F, B>
{
    type Base = Base<'a, B>;

    fn base_context(self) -> Self::Base {
        self.base_ctx.inner
    }
}

impl<F: ExtendableField, B: ShardBinding> Debug for Upgraded<'_, F, B> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext<{:?}>", type_name::<F>())
    }
}

/// Upgrading a semi-honest replicated share using malicious context produces
/// a MAC-secured share with the same vectorization factor.
#[async_trait]
impl<'a, V: ExtendableFieldSimd<N>, B: ShardBinding, const N: usize> Upgradable<Upgraded<'a, V, B>>
    for Replicated<V, N>
where
    Replicated<<V as ExtendableField>::ExtendedField, N>: FromPrss,
{
    type Output = MaliciousReplicated<V, N>;

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V, B>,
        record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        let ctx = ctx.narrow(&UpgradeStep);
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
        let induced_share = self.induced();
        // expand r to match the vectorization factor of induced share
        let r = ctx.r_share(record_id).expand();

        let narrowed = ctx.narrow(&RandomnessForValidation);
        let rx = semi_honest_multiply(ctx.base_context(), record_id, &induced_share, &r).await?;
        let m = MaliciousReplicated::new(self, rx);
        narrowed.accumulate_macs(record_id, &m);

        Ok(m)
    }
}

/// Convenience trait implementations to upgrade test data.
#[cfg(all(test, descriptive_gate))]
#[async_trait]
impl<'a, V: ExtendableFieldSimd<N>, B: ShardBinding, const N: usize> Upgradable<Upgraded<'a, V, B>>
    for (Replicated<V, N>, Replicated<V, N>)
where
    Replicated<<V as ExtendableField>::ExtendedField, N>: FromPrss,
{
    type Output = (MaliciousReplicated<V, N>, MaliciousReplicated<V, N>);

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V, B>,
        record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        let (l, r) = self;
        let l = l.upgrade(ctx.narrow("upgrade_l"), record_id).await?;
        let r = r.upgrade(ctx.narrow("upgrade_r"), record_id).await?;
        Ok((l, r))
    }
}

#[cfg(all(test, descriptive_gate))]
#[async_trait]
impl<'a, V: ExtendableField, B: ShardBinding> Upgradable<Upgraded<'a, V, B>> for () {
    type Output = ();

    async fn upgrade(
        self,
        _context: Upgraded<'a, V, B>,
        _record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        Ok(())
    }
}

#[cfg(all(test, descriptive_gate))]
#[async_trait]
impl<'a, V, U, B> Upgradable<Upgraded<'a, V, B>> for Vec<U>
where
    V: ExtendableField,
    U: Upgradable<Upgraded<'a, V, B>, Output: Send> + Send + 'a,
    B: ShardBinding,
{
    type Output = Vec<U::Output>;

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V, B>,
        record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        /// Need a standalone function to avoid GAT issue that apparently can manifest
        /// even with `async_trait`.
        fn upgrade_vec<'a, V, U, B>(
            ctx: Upgraded<'a, V, B>,
            record_id: RecordId,
            input: Vec<U>,
        ) -> impl std::future::Future<Output = Result<Vec<U::Output>, Error>> + 'a
        where
            V: ExtendableField,
            U: Upgradable<Upgraded<'a, V, B>> + 'a,
            B: ShardBinding,
        {
            let mut upgraded = Vec::with_capacity(input.len());
            async move {
                for (i, item) in input.into_iter().enumerate() {
                    let ctx = ctx.narrow(&format!("upgrade-vec-{i}"));
                    // FQN syntax fixes the GAT issue, `item.upgrade` does not work
                    // (I know, its crazy)
                    let v = Upgradable::upgrade(item, ctx, record_id).await?;
                    upgraded.push(v);
                }
                Ok(upgraded)
            }
        }

        crate::seq_join::assert_send(upgrade_vec(ctx, record_id, self)).await
    }
}
