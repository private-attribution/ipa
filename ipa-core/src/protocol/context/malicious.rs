use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use async_trait::async_trait;
use ipa_step::{Step, StepNarrow};

use crate::{
    error::Error,
    helpers::{ChannelId, Gateway, MpcMessage, MpcReceivingEnd, Role, SendingEnd, TotalRecords},
    protocol::{
        basics::{
            mul::{semi_honest_multiply, step::MaliciousMultiplyStep::RandomnessForValidation},
            ShareKnownValue,
        },
        context::{
            dzkp_malicious::DZKPUpgraded,
            dzkp_validator::{DZKPBatch, MaliciousDZKPValidator},
            prss::InstrumentedIndexedSharedRandomness,
            step::UpgradeStep,
            upgrade::Upgradable,
            validator::{Malicious as Validator, MaliciousAccumulator},
            Base, Context as ContextTrait, InstrumentedSequentialSharedRandomness,
            SpecialAccessToUpgradedContext, UpgradableContext, UpgradedContext,
        },
        prss::{Endpoint as PrssEndpoint, FromPrss},
        Gate, RecordId,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, ExtendableField, ExtendableFieldSimd},
        semi_honest::AdditiveShare as Replicated,
    },
    seq_join::SeqJoin,
    sharding::NotSharded,
    sync::Arc,
};

#[derive(Clone)]
pub struct Context<'a> {
    inner: Base<'a>,
}

impl<'a> Context<'a> {
    pub fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self::new_with_gate(participant, gateway, Gate::default())
    }

    pub fn new_with_gate(participant: &'a PrssEndpoint, gateway: &'a Gateway, gate: Gate) -> Self {
        Self {
            inner: Base::new_complete(
                participant,
                gateway,
                gate,
                TotalRecords::Unspecified,
                NotSharded,
            ),
        }
    }

    /// Upgrade this context to malicious using MACs.
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `upgrade_step` is the step that will be used for upgrading inputs
    /// from `replicated::semi_honest::AdditiveShare` to `replicated::malicious::AdditiveShare`.
    /// `accumulator` and `r_share` come from a `MaliciousValidator`.
    #[must_use]
    pub fn upgrade<S: Step + ?Sized, F: ExtendableField>(
        self,
        malicious_step: &S,
        accumulator: MaliciousAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> Upgraded<'a, F>
    where
        Gate: StepNarrow<S>,
    {
        Upgraded::new(&self.inner, malicious_step, accumulator, r_share)
    }

    /// Upgrade this context to malicious using DZKPs
    /// `malicious_step` is the step that will be used for malicious protocol execution.
    /// `DZKPBatch` comes from a `MaliciousDZKPValidator`.
    #[must_use]
    pub fn dzkp_upgrade<S: Step + ?Sized>(
        self,
        malicious_step: &S,
        batch: DZKPBatch,
    ) -> DZKPUpgraded<'a>
    where
        Gate: StepNarrow<S>,
    {
        DZKPUpgraded::new(&self.inner, malicious_step, batch)
    }

    pub(crate) fn validator_context(self) -> Base<'a> {
        // The DZKP validator uses communcation channels internally. We don't want any TotalRecords
        // set by the protocol to apply to those channels.
        Base {
            total_records: TotalRecords::Unspecified,
            ..self.inner
        }
    }
}

impl<'a> super::Context for Context<'a> {
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

impl<'a> UpgradableContext for Context<'a> {
    type Validator<F: ExtendableField> = Validator<'a, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F> {
        Validator::new(self)
    }

    type DZKPValidator = MaliciousDZKPValidator<'a>;

    fn dzkp_validator(self, max_multiplications_per_gate: usize) -> Self::DZKPValidator {
        MaliciousDZKPValidator::new(self, max_multiplications_per_gate)
    }
}

impl<'a> SeqJoin for Context<'a> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.active_work()
    }
}

impl Debug for Context<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext")
    }
}

/// Represents protocol context in malicious setting, i.e. secure against one active adversary
/// in 3 party MPC ring.
#[derive(Clone)]
pub struct Upgraded<'a, F: ExtendableField> {
    /// TODO (alex): Arc is required here because of the `TestWorld` structure. Real world
    /// may operate with raw references and be more efficient
    inner: Arc<UpgradedInner<'a, F>>,
    gate: Gate,
    total_records: TotalRecords,
}

impl<'a, F: ExtendableField> Upgraded<'a, F> {
    pub(super) fn new<S: Step + ?Sized>(
        source: &Base<'a>,
        malicious_step: &S,
        acc: MaliciousAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> Self
    where
        Gate: StepNarrow<S>,
    {
        Self {
            inner: UpgradedInner::new(source, acc, r_share),
            gate: source.gate().narrow(malicious_step),
            total_records: TotalRecords::Unspecified,
        }
    }

    // TODO: it can be made more efficient by impersonating malicious context as semi-honest
    // it does not work as of today because of https://github.com/rust-lang/rust/issues/20400
    // while it is possible to define a struct that wraps a reference to malicious context
    // and implement `Context` trait for it, implementing SecureMul and Reveal for Context
    // is not.
    // For the same reason, it is not possible to implement Context<F, Share = Replicated<F>>
    // for `MaliciousContext`. Deep clone is the only option.
    fn as_base(&self) -> Base<'a> {
        Base::new_complete(
            self.inner.prss,
            self.inner.gateway,
            self.gate.clone(),
            self.total_records,
            NotSharded,
        )
    }

    pub fn share_known_value(&self, value: F) -> MaliciousReplicated<F> {
        MaliciousReplicated::new(
            Replicated::share_known_value(&self.clone().base_context(), value),
            &self.inner.r_share * value.to_extended(),
        )
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
        self.inner
            .accumulator
            .accumulate_macs(&self.prss(), record_id, share);
    }

    /// It is intentionally not public, allows access to it only from within
    /// this module
    fn r_share(&self) -> &Replicated<F::ExtendedField> {
        &self.inner.r_share
    }
}

#[async_trait]
impl<'a, F: ExtendableField> UpgradedContext for Upgraded<'a, F> {
    type Field = F;
}

impl<'a, F: ExtendableField> super::Context for Upgraded<'a, F> {
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

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.inner
            .gateway
            .get_mpc_receiver(&ChannelId::new(role, self.gate.clone()))
    }
}

impl<'a, F: ExtendableField> SeqJoin for Upgraded<'a, F> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.gateway.config().active_work()
    }
}

/// Sometimes it is required to reinterpret malicious context as semi-honest. Ideally
/// protocols should be generic over `SecretShare` trait and not requiring this cast and taking
/// `ProtocolContext<'a, S: SecretShare<F>, F: Field>` as the context. If that is not possible,
/// this implementation makes it easier to reinterpret the context as semi-honest.
impl<'a, F: ExtendableField> SpecialAccessToUpgradedContext<F> for Upgraded<'a, F> {
    type Base = Base<'a>;

    fn base_context(self) -> Self::Base {
        self.as_base()
    }
}

impl<F: ExtendableField> Debug for Upgraded<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousContext<{:?}>", type_name::<F>())
    }
}
struct UpgradedInner<'a, F: ExtendableField> {
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    accumulator: MaliciousAccumulator<F>,
    r_share: Replicated<F::ExtendedField>,
}

impl<'a, F: ExtendableField> UpgradedInner<'a, F> {
    fn new(
        base_context: &Base<'a>,
        accumulator: MaliciousAccumulator<F>,
        r_share: Replicated<F::ExtendedField>,
    ) -> Arc<Self> {
        Arc::new(UpgradedInner {
            prss: base_context.inner.prss,
            gateway: base_context.inner.gateway,
            accumulator,
            r_share,
        })
    }

    fn accumulator(&self) -> &MaliciousAccumulator<F> {
        &self.accumulator
    }
}

/// Upgrading a semi-honest replicated share using malicious context produces
/// a MAC-secured share with the same vectorization factor.
#[async_trait]
impl<'a, V: ExtendableFieldSimd<N>, const N: usize> Upgradable<Upgraded<'a, V>> for Replicated<V, N>
where
    Replicated<<V as ExtendableField>::ExtendedField, N>: FromPrss,
{
    type Output = MaliciousReplicated<V, N>;

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V>,
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
        let r = ctx.r_share().expand();

        let rx = semi_honest_multiply(ctx.as_base(), record_id, &induced_share, &r).await?;
        let m = MaliciousReplicated::new(self, rx);
        let narrowed = ctx.narrow(&RandomnessForValidation);
        let prss = narrowed.prss();
        let accumulator = narrowed.inner.accumulator();
        accumulator.accumulate_macs(&prss, record_id, &m);

        Ok(m)
    }
}

/// Convenience trait implementations to upgrade test data.

#[cfg(all(test, descriptive_gate))]
#[async_trait]
impl<'a, V: ExtendableFieldSimd<N>, const N: usize> Upgradable<Upgraded<'a, V>>
    for (Replicated<V, N>, Replicated<V, N>)
where
    Replicated<<V as ExtendableField>::ExtendedField, N>: FromPrss,
{
    type Output = (MaliciousReplicated<V, N>, MaliciousReplicated<V, N>);

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V>,
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
impl<'a, V: ExtendableField> Upgradable<Upgraded<'a, V>> for () {
    type Output = ();

    async fn upgrade(
        self,
        _context: Upgraded<'a, V>,
        _record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        Ok(())
    }
}

#[cfg(all(test, descriptive_gate))]
#[async_trait]
impl<'a, V, U> Upgradable<Upgraded<'a, V>> for Vec<U>
where
    V: ExtendableField,
    U: Upgradable<Upgraded<'a, V>, Output: Send> + Send + 'a,
{
    type Output = Vec<U::Output>;

    async fn upgrade(
        self,
        ctx: Upgraded<'a, V>,
        record_id: RecordId,
    ) -> Result<Self::Output, Error> {
        /// Need a standalone function to avoid GAT issue that apparently can manifest
        /// even with `async_trait`.
        fn upgrade_vec<'a, V, U>(
            ctx: Upgraded<'a, V>,
            record_id: RecordId,
            input: Vec<U>,
        ) -> impl std::future::Future<Output = Result<Vec<U::Output>, Error>> + 'a
        where
            V: ExtendableField,
            U: Upgradable<Upgraded<'a, V>> + 'a,
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
