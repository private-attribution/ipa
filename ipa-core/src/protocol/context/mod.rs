pub mod dzkp_field;
pub mod dzkp_malicious;
pub mod dzkp_semi_honest;
pub mod dzkp_validator;
pub mod malicious;
pub mod prss;
pub mod semi_honest;
pub mod step;
pub mod upgrade;

/// Validators are not used in IPA v3 yet. Once we make use of MAC-based validation,
/// this flag can be removed
#[allow(dead_code)]
pub mod validator;

use std::{collections::HashMap, iter, num::NonZeroUsize, pin::pin};

use async_trait::async_trait;
pub use dzkp_malicious::DZKPUpgraded as DZKPUpgradedMaliciousContext;
pub use dzkp_semi_honest::DZKPUpgraded as DZKPUpgradedSemiHonestContext;
use futures::{stream, Stream, StreamExt};
use ipa_step::{Step, StepNarrow};
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
        ChannelId, Direction, Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd,
        ShardReceivingEnd, TotalRecords,
    },
    protocol::{
        context::dzkp_validator::{DZKPValidator, Segment},
        prss::{Endpoint as PrssEndpoint, SharedRandomness},
        Gate, RecordId,
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

    /// Requests data to be received from another MPC helper. Receive requests [`MpcReceivingEnd::receive`]
    /// can be issued from multiple threads.
    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M>;
}

pub trait UpgradableContext: Context {
    type Validator<F: ExtendableField>: Validator<F>;

    fn validator<F: ExtendableField>(self) -> Self::Validator<F>;

    type DZKPUpgradedContext: DZKPContext;
    type DZKPValidator: DZKPValidator<Self>;

    fn dzkp_validator(self, max_multiplications_per_gate: usize) -> Self::DZKPValidator;
}

#[async_trait]
pub trait UpgradedContext: Context {
    type Field: ExtendableField;
    type Share: SecretSharing<Self::Field> + 'static;

    async fn upgrade_one(
        &self,
        record_id: RecordId,
        x: Replicated<Self::Field>,
    ) -> Result<Self::Share, Error>;

    /// Upgrade an input using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade<T, M>(&self, input: T) -> Result<M, Error>
    where
        T: Send,
        UpgradeContext<Self>: UpgradeToMalicious<T, M>,
    {
        #[cfg(descriptive_gate)]
        {
            use crate::protocol::{context::step::UpgradeStep, NoRecord};

            UpgradeContext::new(self.narrow(&UpgradeStep), NoRecord)
                .upgrade(input)
                .await
        }
        #[cfg(not(descriptive_gate))]
        {
            let _ = input;
            unimplemented!()
        }
    }

    /// Upgrade an input for a specific bit index and record using this context.
    /// # Errors
    /// When the multiplication fails. This does not include additive attacks
    /// by other helpers.  These are caught later.
    async fn upgrade_for<T, M>(&self, record_id: RecordId, input: T) -> Result<M, Error>
    where
        T: Send,
        UpgradeContext<Self, RecordId>: UpgradeToMalicious<T, M>,
    {
        #[cfg(descriptive_gate)]
        {
            use crate::protocol::context::step::UpgradeStep;

            UpgradeContext::new(self.narrow(&UpgradeStep), record_id)
                .upgrade(input)
                .await
        }
        #[cfg(not(descriptive_gate))]
        {
            let _ = (record_id, input);
            unimplemented!()
        }
    }
}

pub trait SpecialAccessToUpgradedContext<F: ExtendableField>: UpgradedContext {
    /// This is the base context type.  This will always be `Base`, but use
    /// an associated type to avoid having to bind this trait to the lifetime
    /// associated with the `Base` struct.
    type Base: Context;

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

impl ShardedContext for Base<'_, Sharded> {
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M> {
        self.inner.gateway.get_shard_sender(
            &ChannelId::new(dest_shard, self.gate.clone()),
            self.total_records,
        )
    }

    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M> {
        self.inner
            .gateway
            .get_shard_receiver(&ChannelId::new(origin, self.gate.clone()))
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

    fn recv_channel<M: MpcMessage>(&self, role: Role) -> MpcReceivingEnd<M> {
        self.inner
            .gateway
            .get_mpc_receiver(&ChannelId::new(role, self.gate.clone()))
    }
}

/// Context for MPC circuits that can operate on multiple shards. Provides access to shard information
/// via [`ShardConfiguration`] trait.
pub trait ShardedContext: Context + ShardConfiguration {
    /// Open a communication channel to another shard within the same MPC helper. Similarly to
    /// [`Self::send_channel`], it can be requested more than once for the same channel and from
    /// multiple threads, but it should not be required. See [`Self::shard_recv_channel`].
    fn shard_send_channel<M: Message>(&self, dest_shard: ShardIndex) -> SendingEnd<ShardIndex, M>;

    /// Request a stream to be received from a peer shard within the same MPC helper. This method
    /// can be called only once per communication channel.
    ///
    /// ## Panics
    /// If called more than once for the same origin and on context instance, narrowed to the same
    /// [`Self::gate`].
    fn shard_recv_channel<M: Message>(&self, origin: ShardIndex) -> ShardReceivingEnd<M>;

    /// Requests data to be received from all shards that are registered in the system.
    /// Shards that don't have any data to send, must explicitly open and close the send channel.
    fn recv_from_shards<M: Message>(
        &self,
    ) -> impl Stream<Item = (ShardIndex, Result<M, crate::error::Error>)> + Send {
        stream::select_all(
            self.peer_shards()
                .map(|origin| self.shard_recv_channel(origin).map(move |v| (origin, v))),
        )
    }

    /// Picks a shard according to the value obtained from sampling PRSS.
    /// The `direction` argument indicates if the `left` or `right` PRSS is utilized.
    fn pick_shard(&self, record_id: RecordId, direction: Direction) -> ShardIndex {
        // FIXME(1029): update PRSS trait to compute only left or right part
        let (l, r): (u128, u128) = self.prss().generate(record_id);
        let shard_index = u32::try_from(
            match direction {
                Direction::Left => l,
                Direction::Right => r,
            } % u128::from(self.shard_count()),
        )
        .expect("Number of shards should not exceed u32 capacity");

        ShardIndex::from(shard_index)
    }
}

impl ShardConfiguration for Base<'_, Sharded> {
    fn shard_id(&self) -> ShardIndex {
        self.sharding.shard_id
    }

    fn shard_count(&self) -> ShardIndex {
        self.sharding.shard_count
    }
}

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

/// Reshards the given set of shares across all shards available on the current helper. It uses the
/// provided function to determine destination shards for each input row.
///
/// The resulting vector contains all shares sent to this shard by other shards and shares selected
/// locally by `shard_picker` fn to stay on this shard.
///
/// Resharding opens one communication channel per peer (N^2 channels will be open in total,
/// N per shard). Each channel stays open until the very last row is processed, then they are explicitly
/// closed, even if nothing has been communicated between that pair.
///
/// ## Shard picking considerations
/// It is expected for `shard_picker` to select shards uniformly, by either using [`prss`] or sampling
/// random values with enough entropy. Failure to do so may lead to extra memory overhead - this
/// function uses the conservative `1.2` coefficent to estimate the number of records per shard after
/// resharding is completed, according to our [`calculations`] that is sufficient with 2^-60 failure
/// probability. This is a very conservative estimate, assuming 1M events per shard and 100k shards.
///
/// [`calculations`]: https://docs.google.com/document/d/1vej6tYgNV3GWcldD4tl7a4Z9EeZwda3F5u7roPGArlU/
///
/// ## Panics
/// When `shard_picker` returns an out-of-bounds index.
///
/// ## Errors
/// If cross-shard communication fails
pub async fn reshard<L, K, C, S>(
    ctx: C,
    input: L,
    shard_picker: S,
) -> Result<Vec<K>, crate::error::Error>
where
    L: IntoIterator<Item = K>,
    L::IntoIter: ExactSizeIterator,
    S: Fn(C, RecordId, &K) -> ShardIndex,
    K: Message + Clone,
    C: ShardedContext,
{
    let input = input.into_iter();
    let input_len = input.len();

    // We set channels capacity to be at least 1 to be able to open send channels to all peers.
    // It is prohibited to create them if total records is not set. We also over-provision here
    // because it is not known in advance how many records each peer receives. We could've set
    // the channel capacity to be indeterminate, but it could be less efficient in using our most
    // precious resource - network.
    let ctx =
        ctx.set_total_records(TotalRecords::specified(input_len).unwrap_or(TotalRecords::ONE));
    let my_shard = ctx.shard_id();

    // Open communication channels to all shards on this helper and keep track of records sent
    // through any of them.
    let mut send_channels = ctx
        .peer_shards()
        .map(|shard_id| {
            (
                shard_id,
                (RecordId::FIRST, ctx.shard_send_channel::<K>(shard_id)),
            )
        })
        .collect::<HashMap<_, _>>();

    // Request data from all shards.
    let rcv_stream = ctx
        .recv_from_shards::<K>()
        .map(|(shard_id, v)| {
            (
                shard_id,
                v.map(Option::Some).map_err(crate::error::Error::from),
            )
        })
        .fuse();

    // This produces a stream of outcomes of send requests.
    // In order to make it compatible with receive stream, it also returns records that must
    // stay on this shard, according to `shard_picker`'s decision.
    // That gives an awkward interface for output: (destination shard, Result<Option<Value>>)
    // The second argument is set to Err if we failed to send the value out. This will fail the
    // whole resharding process.
    // If send was successful, we set the argument to Ok(None). Only records assigned to this shard
    // by the `shard_picker` will have the value of Ok(Some(Value))
    let send_stream = futures::stream::unfold(
        // it is crucial that the following execution is completed sequentially, in order for record id
        // tracking per shard to work correctly. If tasks complete out of order, this will cause share
        // misplacement on the recipient side.
        (
            input.enumerate().zip(iter::repeat(ctx.clone())),
            &mut send_channels,
        ),
        |(mut input, send_channels)| async {
            // Process more data as it comes in, or close the sending channels, if there is nothing
            // left.
            if let Some(((i, val), ctx)) = input.next() {
                let dest_shard = shard_picker(ctx, RecordId::from(i), &val);
                if dest_shard == my_shard {
                    Some(((my_shard, Ok(Some(val.clone()))), (input, send_channels)))
                } else {
                    let (record_id, se) = send_channels.get_mut(&dest_shard).unwrap();
                    let send_result = se
                        .send(*record_id, val)
                        .await
                        .map_err(crate::error::Error::from)
                        .map(|()| None);
                    *record_id += 1;
                    Some(((my_shard, send_result), (input, send_channels)))
                }
            } else {
                for (last_record, send_channel) in send_channels.values() {
                    send_channel.close(*last_record).await;
                }
                None
            }
        },
    )
    .fuse();
    let shard_records_est = {
        let v = input_len / usize::from(ctx.shard_count());
        // this gives us ~ 1.25 capacity, very close to 1.26 overhead estimated
        // If 25% extra capacity becomes a problem and number of events/shards is not close
        // to the worst case, this can be tuned down to 1.01
        v + v / 4
    };

    // This contains the deterministic order of events after resharding is complete.
    // Each shard will hold the records in this order:
    // [shard_0_records], [shard_1_records], ..., [shard_N].
    // There is no reason why this strategy was chosen. As long as it is consistent across helpers,
    // other ways to build the total order work too. For example, we could put records with
    // record_id = 0 first, then records with record_id = 1, etc.
    let mut r: Vec<Vec<_>> = ctx
        .shard_count()
        .iter()
        .map(|_| Vec::with_capacity(shard_records_est))
        .collect();

    // Interleave send and receive streams to ensure the backpressure does not block the flow.
    // For example, if this shard just sends all the data and then receives, the flow control from
    // another shard (say S2) may prevent it from sending more data until it receives records from
    // S2.
    // This approach makes sure we do what we can - send or receive.
    let mut send_recv = pin!(futures::stream::select(send_stream, rcv_stream));

    while let Some((shard_id, v)) = send_recv.next().await {
        if let Some(m) = v? {
            r[usize::from(shard_id)].push(m);
        }
    }

    Ok(r.into_iter().flatten().collect())
}

/// trait for contexts that allow MPC multiplications that are protected against a malicious helper by using a DZKP
pub trait DZKPContext: Context {
    /// `is_verified()` allows to confirm that there are currently no unverified multiplications,
    /// i.e. shares that might have been manipulated.
    /// when this is the case, it is safe to call functions like `reveal`
    ///
    /// ## Errors
    /// Returns error when context contains unverified multiplications
    fn is_verified(&self) -> Result<(), Error>;

    /// This function allows to add segments to a batch. This function is called by `multiply` to add
    /// values that need to be verified using the DZKP prover and verifiers.
    fn push(&self, record_id: RecordId, segment: Segment);
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{iter, iter::repeat};

    use futures::{future::join_all, stream::StreamExt, try_join};
    use ipa_step::StepNarrow;
    use rand::{
        distributions::{Distribution, Standard},
        Rng,
    };
    use typenum::Unsigned;

    use crate::{
        ff::{
            boolean_array::{BA3, BA64, BA8},
            Field, Fp31, Serializable, U128Conversions,
        },
        helpers::{Direction, Role},
        protocol::{
            basics::ShareKnownValue,
            context::{
                reshard, step::MaliciousProtocolStep::MaliciousProtocol, Context, ShardedContext,
                UpgradableContext, UpgradedContext, Validator,
            },
            prss::SharedRandomness,
            RecordId,
        },
        secret_sharing::replicated::{
            malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        sharding::{ShardConfiguration, ShardIndex},
        telemetry::metrics::{
            BYTES_SENT, INDEXED_PRSS_GENERATED, RECORDS_SENT, SEQUENTIAL_PRSS_GENERATED,
        },
        test_executor::run,
        test_fixture::{
            Reconstruct, RoundRobinInputDistribution, Runner, TestWorld, TestWorldConfig,
            WithShards,
        },
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
        let metrics_step = world.gate().narrow("metrics");

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
        let metrics_step = world
            .gate()
            // TODO: leaky abstraction, test world should tell us the exact step
            .narrow(&MaliciousProtocol)
            .narrow("metrics");

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

        let input_size = input.len();
        let snapshot = world.metrics_snapshot();

        // Malicious protocol has an amplification factor of 3 and constant overhead of 5. For each input row it
        // (input size) upgrades input to malicious
        // (input size) executes toy protocol
        // (input size) propagates u and w
        // (1) multiply r * share of zero
        // (4) reveals r (2 for check_zero, 2 for validate)
        let comm_factor = |input_size| 3 * input_size + 5;
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

    #[test]
    fn receive_from_all_shards() {
        type Field = BA3;
        type Share = Replicated<Field>;

        run(|| async move {
            let world = TestWorld::<WithShards<3>>::with_shards(TestWorldConfig::default());
            let r = world
                .semi_honest(iter::empty::<()>(), |ctx, _| async move {
                    let ctx = ctx.set_total_records(1);
                    if ctx.shard_id() == ShardIndex::FIRST {
                        let mut r = vec![Vec::new(); ctx.shard_count().into()];
                        let mut recv_stream = ctx.recv_from_shards::<Share>();
                        while let Some((from, share)) = recv_stream.next().await {
                            r[usize::from(from)].push(share.unwrap());
                        }

                        r.into_iter().flatten().collect()
                    } else if ctx.shard_id() == ShardIndex::from(1) {
                        ctx.shard_send_channel(ShardIndex::FIRST)
                            .send(
                                RecordId::FIRST,
                                Share::share_known_value(&ctx, Field::try_from(1).unwrap()),
                            )
                            .await
                            .unwrap();

                        Vec::new()
                    } else {
                        // Explicit FIN is required from each shard, when `recv_from_shards` is used.
                        // `reshard` functionality is more convenient to use.
                        ctx.shard_send_channel::<Share>(ShardIndex::FIRST)
                            .close(RecordId::FIRST)
                            .await;
                        Vec::new()
                    }
                })
                .await
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            assert_eq!(vec![Field::try_from(1).unwrap()], r);
        });
    }

    /// Ensure global record order across shards is consistent.
    #[test]
    fn shard_picker() {
        run(|| async move {
            const SHARDS: u32 = 5;
            let world: TestWorld<WithShards<5, RoundRobinInputDistribution>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input: Vec<_> = (0..SHARDS).map(BA8::truncate_from).collect();
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    reshard(ctx, shard_input, |_, record_id, _| {
                        ShardIndex::from(u32::from(record_id) % SHARDS)
                    })
                    .await
                    .unwrap()
                })
                .await
                .into_iter()
                .flat_map(|v| v.reconstruct())
                .collect::<Vec<_>>();

            assert_eq!(input, r);
        });
    }

    #[test]
    fn prss_one_side() {
        run(|| async {
            let input = ();
            let world = TestWorld::default();

            world
                .semi_honest(input, |ctx, ()| async move {
                    let left_value: BA64 = ctx
                        .prss()
                        .generate_one_side(RecordId::FIRST, Direction::Left);
                    let right_value = ctx
                        .prss()
                        .generate_one_side(RecordId::FIRST, Direction::Right);

                    Replicated::new(left_value, right_value)
                })
                .await
                // reconstruct validates that sharings are valid
                .reconstruct();
        });
    }
}
