pub mod dzkp_field;
pub mod dzkp_malicious;
pub mod dzkp_semi_honest;
pub mod dzkp_validator;
pub mod malicious;
pub mod prss;
pub mod semi_honest;
pub mod step;
pub mod upgrade;

mod batcher;
pub mod validator;

use std::{collections::HashMap, num::NonZeroUsize, pin::pin};

use async_trait::async_trait;
pub use dzkp_malicious::DZKPUpgraded as DZKPUpgradedMaliciousContext;
pub use dzkp_semi_honest::DZKPUpgraded as DZKPUpgradedSemiHonestContext;
use futures::{Stream, StreamExt, TryStreamExt, stream};
use ipa_step::{Step, StepNarrow};
pub use malicious::MaliciousProtocolSteps;
use prss::{InstrumentedIndexedSharedRandomness, InstrumentedSequentialSharedRandomness};
pub use semi_honest::Upgraded as UpgradedSemiHonestContext;
pub use validator::Validator;
pub type SemiHonestContext<'a, B = NotSharded> = semi_honest::Context<'a, B>;
pub type ShardedSemiHonestContext<'a> = semi_honest::Context<'a, Sharded>;

pub type MaliciousContext<'a, B = NotSharded> = malicious::Context<'a, B>;
pub type ShardedMaliciousContext<'a> = malicious::Context<'a, Sharded>;
pub type UpgradedMaliciousContext<'a, F, B = NotSharded> = malicious::Upgraded<'a, F, B>;
pub type ShardedUpgradedMaliciousContext<'a, F, B = Sharded> = malicious::Upgraded<'a, F, B>;

#[cfg(all(feature = "in-memory-infra", any(test, feature = "test-fixture")))]
pub(crate) use malicious::TEST_DZKP_STEPS;

use crate::{
    error::Error,
    helpers::{
        ChannelId, Direction, Gateway, Message, MpcMessage, MpcReceivingEnd, Role, SendingEnd,
        ShardReceivingEnd, TotalRecords, stream::ExactSizeStream,
    },
    protocol::{
        Gate, RecordId,
        context::dzkp_validator::DZKPValidator,
        prss::{Endpoint as PrssEndpoint, SharedRandomness},
    },
    secret_sharing::replicated::malicious::ExtendableField,
    seq_join::SeqJoin,
    sharding::{NotSharded, ShardBinding, ShardConfiguration, ShardIndex, Sharded},
    utils::NonZeroU32PowerOfTwo,
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
        InstrumentedSequentialSharedRandomness<'_>,
        InstrumentedSequentialSharedRandomness<'_>,
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

    type DZKPValidator: DZKPValidator;

    fn dzkp_validator<S>(
        self,
        steps: MaliciousProtocolSteps<S>,
        max_multiplications_per_gate: usize,
    ) -> Self::DZKPValidator
    where
        Gate: StepNarrow<S>,
        S: Step + ?Sized;
}

pub type MacUpgraded<C, F> = <<C as UpgradableContext>::Validator<F> as Validator<F>>::Context;
pub type DZKPUpgraded<C> = <<C as UpgradableContext>::DZKPValidator as DZKPValidator>::Context;

#[async_trait]
pub trait UpgradedContext: Context {
    type Field: ExtendableField;

    /// This method blocks until `record_id` has been validated. Validation happens
    /// in batches, this method will block each individual future until
    /// the whole batch is validated. The code written this way is more concise
    /// and easier to read
    ///
    /// Future improvement will combine this with [`Reveal`] to access
    /// the value after validation.
    ///
    /// This API may only be used when the number of records per batch is the same
    /// for every step submitting intermediates to this validator. It also requires
    /// that `set_total_records` is set appropriately on the context that is used
    /// to create the validator.
    async fn validate_record(&self, record_id: RecordId) -> Result<(), Error>;
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
    active_work: NonZeroU32PowerOfTwo,
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
            active_work: gateway.config().active_work_as_power_of_two(),
            sharding,
        }
    }

    #[must_use]
    pub fn set_active_work(self, new_active_work: NonZeroU32PowerOfTwo) -> Self {
        Self {
            active_work: new_active_work,
            ..self.clone()
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

    fn cross_shard_prss(&self) -> InstrumentedIndexedSharedRandomness<'_> {
        InstrumentedIndexedSharedRandomness::new(
            self.sharding.cross_shard_prss().indexed(self.gate()),
            self.gate(),
            self.inner.gateway.role(),
        )
    }
}

impl<B: ShardBinding> Context for Base<'_, B> {
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
            active_work: self.active_work,
            sharding: self.sharding.clone(),
        }
    }

    fn set_total_records<T: Into<TotalRecords>>(&self, total_records: T) -> Self {
        Self {
            inner: self.inner.clone(),
            gate: self.gate.clone(),
            total_records: self.total_records.overwrite(total_records),
            active_work: self.active_work,
            sharding: self.sharding.clone(),
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
        self.inner.gateway.get_mpc_sender(
            &ChannelId::new(role, self.gate.clone()),
            self.total_records,
            self.active_work,
        )
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
        let index: u128 = self.prss().generate_one_side(record_id, direction);
        let shard_index = u32::try_from(index % u128::from(self.shard_count()))
            .expect("Number of shards should not exceed u32 capacity");
        ShardIndex::from(shard_index)
    }

    /// Get the indexed PRSS instance shared across all shards on this helper.
    /// Each shard will see the same random values generated by it.
    /// This is still PRSS - the corresponding shards on other helpers will share
    /// the left and the right part
    #[must_use]
    fn cross_shard_prss(&self) -> InstrumentedIndexedSharedRandomness<'_>;
}

impl ShardConfiguration for Base<'_, Sharded> {
    fn shard_id(&self) -> ShardIndex {
        self.sharding.shard_id
    }

    fn shard_count(&self) -> ShardIndex {
        self.sharding.shard_count
    }
}

impl<B: ShardBinding> SeqJoin for Base<'_, B> {
    fn active_work(&self) -> NonZeroUsize {
        self.active_work.to_non_zero_usize()
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
/// ## Stream size
/// [`reshard_try_stream`] takes a regular stream, but will panic at runtime, if the stream
/// upper bound size is not known. Opting out for a runtime check is necessary for it to work
/// with query inputs, where the submitter stream is truncated to take at most `sz` elements.
/// This would mean that stream may have less than `sz` elements and resharding should work.
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
///
/// ## Panics
/// When `shard_picker` returns an out-of-bounds index or if the input stream size
/// upper bound is not known. The latter may be the case for infinite streams.
///
/// ## Errors
/// If cross-shard communication fails or if an input stream
/// yields an `Err` element.
///
pub async fn reshard_try_stream<L, K, C, S>(
    ctx: C,
    input: L,
    shard_picker: S,
) -> Result<Vec<K>, crate::error::Error>
where
    L: Stream<Item = Result<K, crate::error::Error>>,
    S: Fn(C, RecordId, &K) -> ShardIndex,
    K: Message + Clone,
    C: ShardedContext,
{
    let (_, Some(input_len)) = input.size_hint() else {
        panic!("input stream must have size upper bound for resharding to work")
    };

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
        .map(|(shard_id, v)| match v {
            Ok(v) => Ok((shard_id, Some(v))),
            Err(e) => Err(e),
        })
        .fuse();

    let input = pin!(input);
    // Annoying consequence of not having async closures stable. async blocks
    // cannot capture `Copy` values and there is no way to express that
    // only some things need to be moved in Rust
    let mut counter = 0_u32;

    // This produces a stream of outcomes of send requests.
    // In order to make it compatible with receive stream, it also returns records that must
    // stay on this shard, according to `shard_picker`'s decision.
    // That gives an awkward interface for output: (destination shard, Result<Option<Value>>)
    // The second argument is set to Err if we failed to send the value out. This will fail the
    // whole resharding process.
    // If send was successful, we set the argument to Ok(None). Only records assigned to this shard
    // by the `shard_picker` will have the value of Ok(Some(Value))
    let send_stream = futures::stream::try_unfold(
        // it is crucial that the following execution is completed sequentially, in order for record id
        // tracking per shard to work correctly. If tasks complete out of order, this will cause share
        // misplacement on the recipient side.
        (input, &mut send_channels, &mut counter),
        |(mut input, send_channels, i)| {
            let ctx = ctx.clone();
            async {
                // Process more data as it comes in, or close the sending channels, if there is nothing
                // left.
                if let Some(val) = input.try_next().await? {
                    if usize::try_from(*i).unwrap() >= input_len {
                        return Err(crate::error::Error::RecordIdOutOfRange {
                            record_id: RecordId::from(*i),
                            total_records: input_len,
                        });
                    }

                    let dest_shard = shard_picker(ctx, RecordId::from(*i), &val);
                    *i += 1;
                    if dest_shard == my_shard {
                        Ok(Some(((my_shard, Some(val)), (input, send_channels, i))))
                    } else {
                        let (record_id, se) = send_channels.get_mut(&dest_shard).unwrap();
                        se.send(*record_id, val)
                            .await
                            .map_err(crate::error::Error::from)?;
                        *record_id += 1;
                        Ok(Some(((my_shard, None), (input, send_channels, i))))
                    }
                } else {
                    for (last_record, send_channel) in send_channels.values() {
                        send_channel.close(*last_record).await;
                    }
                    Ok(None)
                }
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

    while let Some((shard_id, v)) = send_recv.try_next().await? {
        if let Some(m) = v {
            r[usize::from(shard_id)].push(m);
        }
    }

    Ok(r.into_iter().flatten().collect())
}

/// Provides the same functionality as [`reshard_try_stream`] on
/// infallible streams
///
/// ## Stream size
/// Note that it currently works for streams where size is known in advance. Mainly because
/// we want to set up send buffer sizes and avoid sending records one-by-one to each shard.
/// Other than that, there are no technical limitation here, and it could be possible to make it
/// work with regular streams or opt-out to runtime checks as [`reshard_try_stream`] does.
///
///
/// ```compile_fail
/// use futures::stream::{self, StreamExt};
/// use ipa_core::protocol::context::reshard_stream;
/// use ipa_core::ff::boolean::Boolean;
/// use ipa_core::secret_sharing::SharedValue;
/// async {
///     let a = [Boolean::ZERO];
///     let mut s = stream::iter(a.into_iter()).cycle();
///     // this should fail to compile:
///     // the trait bound `futures::stream::Cycle<...>: ExactSizeStream` is not satisfied
///     reshard_stream(todo!(), s, todo!()).await;
/// };
/// ```
/// ## Panics
/// When `shard_picker` returns an out-of-bounds index.
///
/// ## Errors
/// If cross-shard communication fails
pub async fn reshard_stream<L, K, C, S>(
    ctx: C,
    input: L,
    shard_picker: S,
) -> Result<Vec<K>, crate::error::Error>
where
    L: ExactSizeStream<Item = K>,
    S: Fn(C, RecordId, &K) -> ShardIndex,
    K: Message + Clone,
    C: ShardedContext,
{
    reshard_try_stream(ctx, input.map(Ok), shard_picker).await
}

/// Same as [`reshard_stream`] but takes an iterator with the known size
/// as input.
///
/// ## Panics
/// When `shard_picker` returns an out-of-bounds index.
///
/// ## Errors
/// If cross-shard communication fails
pub async fn reshard_iter<L, K, C, S>(
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
    reshard_stream(ctx, stream::iter(input.into_iter()), shard_picker).await
}

/// trait for contexts that allow MPC multiplications that are protected against a malicious helper by using a DZKP
#[async_trait]
pub trait DZKPContext: Context {
    /// This method blocks until `record_id` has been validated. Validation happens
    /// in batches, this method will block each individual future until
    /// the whole batch is validated. The code written this way is more concise
    /// and easier to read
    ///
    /// Future improvement will combine this with [`Reveal`] to access
    /// the value after validation.
    ///
    /// This API may only be used when the number of records per batch is the same
    /// for every step submitting intermediates to this validator. It also requires
    /// that `set_total_records` is set appropriately on the context that is used
    /// to create the validator.
    async fn validate_record(&self, record_id: RecordId) -> Result<(), Error>;
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{iter, iter::repeat, pin::Pin, task::Poll};

    use futures::{Stream, future::join_all, ready, stream, stream::StreamExt, try_join};
    use ipa_step::StepNarrow;
    use pin_project::pin_project;
    use rand::{
        Rng,
        distributions::{Distribution, Standard},
    };
    use typenum::Unsigned;

    use crate::{
        ff::{
            Field, Fp31, Serializable, U128Conversions,
            boolean_array::{BA3, BA8, BA64},
        },
        helpers::{Direction, Role},
        protocol::{
            RecordId,
            basics::ShareKnownValue,
            context::{
                Context, ShardedContext, UpgradableContext, Validator, reshard_iter,
                reshard_stream, reshard_try_stream, step::MaliciousProtocolStep::MaliciousProtocol,
                upgrade::Upgradable,
            },
            prss::SharedRandomness,
        },
        secret_sharing::{
            SharedValue,
            replicated::{
                ReplicatedSecretSharing,
                malicious::{AdditiveShare as MaliciousReplicated, ExtendableField},
                semi_honest::AdditiveShare as Replicated,
            },
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
    async fn toy_protocol<F, S, C, I>(ctx: C, index: I, share: &S) -> Replicated<F>
    where
        F: Field + U128Conversions,
        Standard: Distribution<F>,
        C: Context,
        S: ReplicatedLeftValue<F>,
        I: Into<RecordId>,
    {
        let ctx = ctx.narrow("metrics");
        let (left_peer, right_peer) = (
            ctx.role().peer(Direction::Left),
            ctx.role().peer(Direction::Right),
        );
        let record_id = index.into();
        let (l, r) = ctx.prss().generate_fields(record_id);

        let (seq_l, seq_r) = {
            let ctx = ctx.narrow(&format!("seq-prss-{record_id}"));
            let (mut left_rng, mut right_rng) = ctx.prss_rng();

            // exercise both methods of `RngCore` trait
            // generating a field value involves calling `next_u64` and 32 bit integer values
            // have special constructor method for them: `next_u32`. Sequential randomness must
            // record metrics for both calls.
            (
                left_rng.r#gen::<F>() + F::truncate_from(left_rng.r#gen::<u32>()),
                right_rng.r#gen::<F>() + F::truncate_from(right_rng.r#gen::<u32>()),
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
        // this will print all metrics if test fails
        println!("{snapshot}");

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
        let field_size = <Fp31 as Serializable>::Size::USIZE;
        let metrics_step = world
            .gate()
            // TODO: leaky abstraction, test world should tell us the exact step
            .narrow(&MaliciousProtocol)
            .narrow("metrics");

        let _result = world
            .upgraded_malicious(input.clone().into_iter(), |ctx, record_id, a| async move {
                let _ = toy_protocol(ctx.clone(), record_id, &a).await;

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
                let v = ctx.set_total_records(1).validator();
                let ctx = v.context().narrow("step1");
                shares.clone().upgrade(ctx, RecordId::FIRST).await.unwrap();
                let ctx = v.context().narrow("step2");
                shares.upgrade(ctx, RecordId::FIRST).await.unwrap();
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
    fn reshard_stream_test() {
        run(|| async move {
            const SHARDS: u32 = 5;
            let world: TestWorld<WithShards<5, RoundRobinInputDistribution>> =
                TestWorld::with_shards(TestWorldConfig::default());

            let input: Vec<_> = (0..SHARDS).map(BA8::truncate_from).collect();
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    let shard_input = stream::iter(shard_input);
                    reshard_stream(ctx, shard_input, |_, record_id, _| {
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

    /// Ensure global record order across shards is consistent.
    #[test]
    fn reshard_iter_test() {
        run(|| async move {
            const SHARDS: u32 = 5;
            let world: TestWorld<WithShards<5, RoundRobinInputDistribution>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input: Vec<_> = (0..SHARDS).map(BA8::truncate_from).collect();
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    reshard_iter(ctx, shard_input, |_, record_id, _| {
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
    fn reshard_try_stream_basic() {
        run(|| async move {
            const SHARDS: u32 = 5;
            let input: Vec<_> = (0..SHARDS).map(BA8::truncate_from).collect();
            let world: TestWorld<WithShards<5>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    reshard_try_stream(ctx, stream::iter(shard_input).map(Ok), |_, record_id, _| {
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
    #[should_panic(expected = "RecordIdOutOfRange { record_id: RecordId(1), total_records: 1 }")]
    fn reshard_try_stream_more_items_than_expected() {
        #[pin_project]
        struct AdversaryStream<S> {
            #[pin]
            inner: S,
            wrong_length: usize,
        }

        impl<S: Stream> AdversaryStream<S> {
            fn new(inner: S, wrong_length: usize) -> Self {
                assert!(wrong_length > 0);
                Self {
                    inner,
                    wrong_length,
                }
            }
        }

        impl<S: Stream> Stream for AdversaryStream<S> {
            type Item = S::Item;

            fn poll_next(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let this = self.project();

                this.inner.poll_next(cx)
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, Some(self.wrong_length))
            }
        }

        run(|| async move {
            const SHARDS: u32 = 5;
            let world: TestWorld<WithShards<5>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input: Vec<_> = (0..5 * SHARDS).map(BA8::truncate_from).collect();
            world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    reshard_try_stream(
                        ctx,
                        AdversaryStream::new(stream::iter(shard_input).map(Ok), 1),
                        |_, _, _| ShardIndex::FIRST,
                    )
                    .await
                    .unwrap()
                })
                .await;
        });
    }

    #[test]
    fn reshard_try_stream_less_items_than_expected() {
        /// This allows advertising higher upper bound limit
        /// that actual number of elements in the stream.
        /// reshard should be able to tolerate that
        #[pin_project]
        struct Wrapper<S> {
            #[pin]
            inner: S,
            expected_len: usize,
        }

        impl<S: Stream> Wrapper<S> {
            fn new(inner: S, expected_len: usize) -> Self {
                assert!(expected_len > 0);
                Self {
                    inner,
                    expected_len,
                }
            }
        }

        impl<S: Stream> Stream for Wrapper<S> {
            type Item = S::Item;

            fn poll_next(
                self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> Poll<Option<Self::Item>> {
                let this = self.project();
                let r = match ready!(this.inner.poll_next(cx)) {
                    Some(val) => {
                        *this.expected_len -= 1;
                        Poll::Ready(Some(val))
                    }
                    None => Poll::Ready(None),
                };

                assert!(
                    *this.expected_len > 0,
                    "Stream should have less elements than expected"
                );
                r
            }

            fn size_hint(&self) -> (usize, Option<usize>) {
                (0, Some(self.expected_len))
            }
        }

        run(|| async move {
            const SHARDS: u32 = 5;
            let world: TestWorld<WithShards<5>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input: Vec<_> = (0..5 * SHARDS).map(BA8::truncate_from).collect();
            let r = world
                .semi_honest(input.clone().into_iter(), |ctx, shard_input| async move {
                    reshard_try_stream(
                        ctx,
                        Wrapper::new(stream::iter(shard_input).map(Ok), 25),
                        |_, record_id, _| ShardIndex::from(u32::from(record_id) % SHARDS),
                    )
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
    #[should_panic(expected = "input stream must have size upper bound for resharding to work")]
    fn reshard_try_stream_infinite() {
        run(|| async move {
            let world: TestWorld<WithShards<5>> =
                TestWorld::with_shards(TestWorldConfig::default());
            world
                .semi_honest(Vec::<BA8>::new().into_iter(), |ctx, _| async move {
                    reshard_try_stream(ctx, stream::repeat(BA8::ZERO).map(Ok), |_, _, _| {
                        ShardIndex::FIRST
                    })
                    .await
                    .unwrap()
                })
                .await;
        });
    }

    #[test]
    fn reshard_try_stream_err() {
        run(|| async move {
            let world: TestWorld<WithShards<5>> =
                TestWorld::with_shards(TestWorldConfig::default());
            world
                .semi_honest(Vec::<BA8>::new().into_iter(), |ctx, _| async move {
                    let err = reshard_try_stream(
                        ctx,
                        stream::iter(vec![
                            Ok(BA8::ZERO),
                            Err(crate::error::Error::InconsistentShares),
                        ]),
                        |_, _, _| ShardIndex::FIRST,
                    )
                    .await
                    .unwrap_err();
                    assert!(matches!(err, crate::error::Error::InconsistentShares));
                })
                .await;
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
