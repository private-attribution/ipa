#[cfg(feature = "descriptive-gate")]
pub mod malicious;
pub mod prss;
pub mod semi_honest;
pub mod upgrade;

/// Validators are not used in IPA v3 yet. Once we make use of MAC-based validation,
/// this flag can be removed
#[allow(dead_code)]
pub mod validator;

use std::num::NonZeroUsize;

use async_trait::async_trait;
#[cfg(feature = "descriptive-gate")]
pub use malicious::{Context as MaliciousContext, Upgraded as UpgradedMaliciousContext};
use prss::{InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness};
pub use semi_honest::Upgraded as UpgradedSemiHonestContext;
pub use upgrade::{UpgradeContext, UpgradeToMalicious};
pub use validator::Validator;
pub type SemiHonestContext<'a, B = NotSharded> = semi_honest::Context<'a, B>;
pub type ShardedSemiHonestContext<'a> = semi_honest::Context<'a, Sharded>;

use crate::{
    error::Error,
    helpers::{
        ChannelId, Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd,
        ShardReceivingEnd, TotalRecords,
    },
    protocol::{
        basics::ZeroPositions,
        prss::Endpoint as PrssEndpoint,
        step::{Gate, Step, StepNarrow},
        RecordId,
    },
    secret_sharing::{
        replicated::{malicious::ExtendableField, semi_honest::AdditiveShare as Replicated},
        SecretSharing,
    },
    seq_join::SeqJoin,
    sharding::{NotSharded, ShardBinding, ShardConfiguration, ShardIndex, Sharded},
};

/// Context used by each helper to perform secure computation. Provides access to shared randomness
/// generator and communication channel.
pub trait Context: Clone + Send + Sync + SeqJoin {
    /// The role of this context.
    fn role(&self) -> Role;

    /// A unique identifier for this stage of the protocol execution.
    #[must_use]
    fn gate(&self) -> &Gate;

    /// Make a sub-context.
    /// Note that each invocation of this should use a unique value of `step`.
    #[must_use]
    fn narrow<S: Step + ?Sized>(&self, step: &S) -> Self
    where
        Gate: StepNarrow<S>;

    /// Sets the context's total number of records field. Communication channels are
    /// closed based on sending the expected total number of records.
    #[must_use]
    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self;

    /// Returns the current setting for the number of records
    #[must_use]
    fn total_records(&self) -> TotalRecords;

    /// Get the indexed PRSS instance for this step.  It is safe to call this function
    /// multiple times.
    ///
    /// # Panics
    /// If `prss_rng()` is invoked for the same context, this will panic.  Use of
    /// these two functions are mutually exclusive.
    #[must_use]
    fn prss(&self) -> InstrumentedIndexedSharedRandomness<'_>;

    /// Get a pair of PRSS-based RNGs.  The first is shared with the helper to the "left",
    /// the second is shared with the helper to the "right".
    ///
    /// # Panics
    /// This method can only be called once.  This is also mutually exclusive with `prss()`.
    /// This will panic if you have previously invoked `prss()`.
    #[must_use]
    fn prss_rng(
        &self,
    ) -> (
        InstrumentedSequentialSharedRandomness,
        InstrumentedSequentialSharedRandomness,
    );

    /// Open a communication channel to an MPC peer. This channel can be requested multiple times
    /// and this method is safe to use in multi-threaded environments.
    fn send_channel<M: MpcMessage>(&self, role: Role) -> SendingEnd<Role, M>;

    /// Open a communication channel to another shard within the same MPC helper. Similarly to
    /// [`Self::send_channel`], it can be requested more than once for the same channel and from
    /// multiple threads, but it should not be required. See [`Self::shard_recv_channel`].
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M>;

    /// Requests data to be received from another MPC helper. Receive requests [`MpcReceivingEnd::receive`]
    /// can be issued from multiple threads.
    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M>;

    /// Request a stream to be received from a peer shard within the same MPC helper. This method
    /// can be called only once per communication channel.
    ///
    /// ## Panics
    /// If called more than once for the same origin and on context instance, narrowed to the same
    /// [`Self::gate`].
    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M>;
}

pub trait UpgradableContext: Context {
    type UpgradedContext<F: ExtendableField>: UpgradedContext<F>;
    type Validator<F: ExtendableField>: Validator<Self, F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F>;
}

#[async_trait]
pub trait UpgradedContext<F: ExtendableField>: Context {
    // TODO: can we add BasicProtocols to this so that we don't need it as a constraint everywhere.
    type Share: SecretSharing<F> + 'static;

    fn share_known_value(&self, value: F) -> Self::Share;

    async fn upgrade_one(
        &self,
        record_id: RecordId,
        x: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error>;

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        T: Send,
        for<'a> UpgradeContext<'a, Self, F>: UpgradeToMalicious<'a, T, M>;

    /// Upgrade an input for a specific bit index and record using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade_for<T, M>(&self, record_id: RecordId, input: T) -> Result<M, Error>
    where
        T: Send,
        for<'a> UpgradeContext<'a, Self, F, RecordId>: UpgradeToMalicious<'a, T, M>;

    /// Upgrade a sparse input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    #[cfg(test)]
    async fn upgrade_sparse(
        &self,
        input: Replicated<F>,
        zeros_at: ZeroPositions,
    ) -> Result<Self::Share, Error>;
}

pub trait SpecialAccessToUpgradedContext<F: ExtendableField>: UpgradedContext<F> {
    /// This is the base context type.  This will always be `Base`, but use
    /// an associated type to avoid having to bind this trait to the lifetime
    /// associated with the `Base` struct.
    type Base: Context;

    /// Take a secret sharing and add it to the running MAC that this context maintains (if any).
    fn accumulate_macs(self, record_id: RecordId, x: &Self::Share);

    /// Get a base context that is an exact copy of this malicious
    /// context, so it will be tied up to the same step and prss.
    #[must_use]
    fn base_context(self) -> Self::Base;
}

/// Context for protocol executions suitable for semi-honest security model, i.e. secure against
/// honest-but-curious adversary parties.
#[derive(Clone)]
pub struct Base<'a, B: ShardBinding = NotSharded> {
    inner: Inner<'a>,
    gate: Gate,
    total_records: TotalRecords,
    /// This indicates whether the system uses sharding or no. It's not ideal that we keep it here
    /// because it gets cloned often, a potential solution to that, if this shows up on flame graph,
    /// would be to move it to [`Inner`] struct.
    sharding: B,
}

impl<'a, B: ShardBinding> Base<'a, B> {
    fn new(participant: &'a PrssEndpoint, gateway: &'a Gateway, sharding: B) -> Self {
        Self::new_complete(
            participant,
            gateway,
            Gate::default(),
            TotalRecords::Unspecified,
            sharding,
        )
    }
}

impl<'a, B: ShardBinding> Base<'a, B> {
    fn new_complete(
        participant: &'a PrssEndpoint,
        gateway: &'a Gateway,
        gate: Gate,
        total_records: TotalRecords,
        sharding: B,
    ) -> Self {
        Self {
            inner: Inner::new(participant, gateway),
            gate,
            total_records,
            sharding,
        }
    }
}

impl<'a, B: ShardBinding> Context for Base<'a, B> {
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
            inner: self.inner.clone(),
            gate: self.gate.narrow(step),
            total_records: self.total_records,
            sharding: self.sharding.clone(),
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: self.gate.clone(),
            total_records: self.total_records.overwrite(total_records),
            sharding: self.sharding.clone(),
        }
    }

    fn total_records(&self) -> TotalRecords {
        self.total_records
    }

    fn prss(&self) -> InstrumentedIndexedSharedRandomness {
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

/// Context for MPC circuits that can operate on multiple shards. Provides access to shard information
/// via [`ShardConfiguration`] trait.
pub trait ShardedContext: Context + ShardConfiguration {}

impl ShardConfiguration for Base<'_, Sharded> {
    fn shard_id(&self) -> ShardIndex {
        self.sharding.shard_id
    }

    fn shard_count(&self) -> ShardIndex {
        self.sharding.shard_count
    }
}

impl<'a> ShardedContext for Base<'a, Sharded> {}

impl<'a, B: ShardBinding> SeqJoin for Base<'a, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.inner.gateway.config().active_work()
    }
}

#[derive(Clone)]
struct Inner<'a> {
    pub prss: &'a PrssEndpoint,
    pub gateway: &'a Gateway,
}

impl<'a> Inner<'a> {
    fn new(prss: &'a PrssEndpoint, gateway: &'a Gateway) -> Self {
        Self { prss, gateway }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::repeat;

    use futures_util::{future::join_all, try_join};
    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use typenum::Unsigned;

    use crate::{
        ff::{Field, Fp31, Serializable, U128Conversions},
        helpers::{Direction, Role},
        protocol::{
            context::{
                validator::Step::MaliciousProtocol, Context, UpgradableContext, UpgradedContext,
                Validator,
            },
            prss::SharedRandomness,
            step::{Gate, StepNarrow},
            RecordId,
        },
        secret_sharing::replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        telemetry::metrics::{
            BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED,
        },
        test_fixture::{Reconstruct, Runner, TestExecutionStep, TestWorld, TestWorldConfig},
    };

    trait ReplicatedLeftValue<F: Field> {
        fn l(&self) -> F;
    }

    impl<F: Field> ReplicatedLeftValue<F> for Replicated<F> {
        fn l(&self) -> F {
            (self as &Replicated<F>).left()
        }
    }

    /// This looks weird because it uses `MaliciousReplicated::rx()` value instead of `x`.
    /// Malicious context intentionally disallows access to `x` without validating first and
    /// here it does not matter at all. It needs just some value to send (any value would do just
    /// fine)
    impl<F: ExtendableField> ReplicatedLeftValue<F::ExtendedField> for MaliciousReplicated<F> {
        fn l(&self) -> F::ExtendedField {
            (self as &MaliciousReplicated<F>).rx().left()
        }
    }

    /// Toy protocol to execute PRSS generation and send/receive logic
    async fn toy_protocol<F, S, C>(ctx: C, index: usize, share: &S) -> Replicated<F>
    where
        F: Field + U128Conversions,
        Standard: Distribution<F>,
        C: Context,
        S: ReplicatedLeftValue<F>,
    {
        let ctx = ctx.narrow("metrics");
        let (left_peer, right_peer) = (
            ctx.role().peer(Direction::Left),
            ctx.role().peer(Direction::Right),
        );
        let record_id = RecordId::from(index);
        let (l, r) = ctx.prss().generate_fields(record_id);

        let (seq_l, seq_r) = {
            let ctx = ctx.narrow(&format!("seq-prss-{index}"));
            let (mut left_rng, mut right_rng) = ctx.prss_rng();

            // exercise both methods of `RngCore` trait
            // generating a field value involves calling `next_u64` and 32 bit integer values
            // have special constructor method for them: `next_u32`. Sequential randomness must
            // record metrics for both calls.
            (
                left_rng.gen::<F>() + F::truncate_from(left_rng.gen::<u32>()),
                right_rng.gen::<F>() + F::truncate_from(right_rng.gen::<u32>()),
            )
        };

        let send_channel = ctx.send_channel(left_peer);
        let recv_channel = ctx.recv_channel::<F>(right_peer);
        let ((), right_share) = try_join!(
            send_channel.send(record_id, share.l() - l - seq_l),
            recv_channel.receive(record_id),
        )
        .unwrap();

        Replicated::new(share.l(), right_share + r + seq_r)
    }

    #[tokio::test]
    async fn semi_honest_metrics() {
        let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());
        let input = (0..10u128).map(Fp31::truncate_from).collect::<Vec<_>>();
        let input_len = input.len();
        let field_size = <Fp31 as Serializable>::Size::USIZE;

        let result = world
            .semi_honest(input.clone().into_iter(), |ctx, shares| async move {
                join_all(
                    shares
                        .iter()
                        .enumerate()
                        .zip(repeat(ctx.set_total_records(input_len)))
                        .map(|((i, share), ctx)| toy_protocol(ctx, i, share)),
                )
                .await
            })
            .await
            .reconstruct();

        // just in case, validate that each helper holds valid shares
        assert_eq!(input, result);

        let input_size = input.len();
        let snapshot = world.metrics_snapshot();
        let metrics_step = Gate::default()
            .narrow(&TestExecutionStep::Iter(0))
            .narrow("metrics");

        // for semi-honest protocols, amplification factor per helper is 1.
        // that is, for every communication, there is exactly one send and receive of the same data
        let records_sent_assert = snapshot
            .assert_metric(RECORDS_SENT)
            .total(3 * input_size)
            .per_step(&metrics_step, 3 * input_size);

        let indexed_prss_assert = snapshot
            .assert_metric(INDEXED_PRSS_GENERATED)
            .total(3 * input_size)
            .per_step(&metrics_step, 3 * input_size);

        let bytes_sent_assert = snapshot
            .assert_metric(BYTES_SENT)
            .total(3 * input_size * field_size)
            .per_step(&metrics_step, 3 * input_size * field_size);

        // each helper generates 2 128 bit values and 2 u32 values
        // resulting in 6 calls to rng::<gen>() per input row
        let seq_prss_assert = snapshot
            .assert_metric(SEQUENTIAL_PRSS_GENERATED)
            .total(6 * 3 * input_size)
            .per_step(&metrics_step.narrow("seq-prss-0"), 6 * 3);

        for role in Role::all() {
            records_sent_assert.per_helper(role, input_size);
            bytes_sent_assert.per_helper(role, field_size * input_size);
            indexed_prss_assert.per_helper(role, input_size);
            seq_prss_assert.per_helper(role, 6 * input_size);
        }
    }

    #[tokio::test]
    async fn malicious_metrics() {
        let world = TestWorld::new_with(TestWorldConfig::default().enable_metrics());
        let input = vec![Fp31::truncate_from(0u128), Fp31::truncate_from(1u128)];
        let input_len = input.len();
        let field_size = <Fp31 as Serializable>::Size::USIZE;

        let _result = world
            .upgraded_malicious(input.clone().into_iter(), |ctx, a| async move {
                let ctx = ctx.set_total_records(input_len);
                join_all(
                    a.iter()
                        .enumerate()
                        .map(|(i, share)| toy_protocol(ctx.clone(), i, share)),
                )
                .await;

                a
            })
            .await;

        let metrics_step = Gate::default()
            .narrow(&TestExecutionStep::Iter(0))
            // TODO: leaky abstraction, test world should tell us the exact step
            .narrow(&MaliciousProtocol)
            .narrow("metrics");

        let input_size = input.len();
        let snapshot = world.metrics_snapshot();

        // Malicious protocol has an amplification factor of 3 and constant overhead of 3. For each input row it
        // (input size) upgrades input to malicious
        // (input size) executes toy protocol
        // (input size) propagates u and w
        // (1) multiply r * share of zero
        // (2) reveals r (1 for check_zero, 1 for validate)
        let comm_factor = |input_size| 3 * input_size + 3;
        let records_sent_assert = snapshot
            .assert_metric(RECORDS_SENT)
            .total(3 * comm_factor(input_size))
            .per_step(&metrics_step, 3 * input_size);

        let bytes_sent_assert = snapshot
            .assert_metric(BYTES_SENT)
            .total(3 * comm_factor(input_size) * field_size)
            .per_step(&metrics_step, 3 * input_size * field_size);

        // PRSS amplification factor is 3 and constant overhead is 5
        // (1) to generate r
        // (1) to generate u
        // (1) to generate w
        // (input_size) to generate random constant later used for validation
        // (input_size) to multiply input by r
        // (input_size) to execute toy protocol
        // (1) to generate randomness for check_zero
        // (1) to multiply output with r
        let prss_factor = |input_size| 3 * input_size + 3 + 1 + 1;
        let indexed_prss_assert = snapshot
            .assert_metric(INDEXED_PRSS_GENERATED)
            .total(3 * prss_factor(input_size))
            .per_step(&metrics_step, 3 * input_size);

        // see semi-honest test for explanation
        let seq_prss_assert = snapshot
            .assert_metric(SEQUENTIAL_PRSS_GENERATED)
            .total(6 * 3 * input_size)
            .per_step(&metrics_step.narrow("seq-prss-0"), 6 * 3);

        for role in Role::all() {
            records_sent_assert.per_helper(role, comm_factor(input_size));
            bytes_sent_assert.per_helper(role, comm_factor(input_size) * field_size);
            indexed_prss_assert.per_helper(role, prss_factor(input_size));
            seq_prss_assert.per_helper(role, 6 * input_size);
        }
    }

    /// validates that malicious upgrade can be called more than once on contexts narrowed down
    /// to unique steps
    #[tokio::test]
    async fn malicious_upgrade() {
        let input = vec![Fp31::truncate_from(0u128), Fp31::truncate_from(1u128)];
        let world = TestWorld::default();

        world
            .malicious(input.into_iter(), |ctx, shares| async move {
                // upgrade shares two times using different contexts
                let v = ctx.validator();
                let ctx = v.context().narrow("step1");
                ctx.upgrade(shares.clone()).await.unwrap();
                let ctx = v.context().narrow("step2");
                ctx.upgrade(shares).await.unwrap();
            })
            .await;
    }
}
