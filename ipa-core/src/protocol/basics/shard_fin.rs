use std::{future::Future, marker::PhantomData, ops::Add};

use futures::{Stream, StreamExt, TryStreamExt};
use generic_array::ArrayLength;
use ipa_step::Step;

use crate::{
    error::{Error, LengthError},
    ff::{boolean::Boolean, boolean_array::BooleanArray, Serializable},
    helpers::{Message, TotalRecords},
    protocol::{
        boolean::step::EightBitStep,
        context::{
            dzkp_validator::DZKPValidator, DZKPContext, DZKPUpgradedMaliciousContext,
            DZKPUpgradedSemiHonestContext, MaliciousProtocolSteps, ShardedContext,
            ShardedMaliciousContext, ShardedSemiHonestContext, UpgradableContext,
        },
        ipa_prf::boolean_ops::addition_sequential::integer_sat_add,
        BooleanProtocols, RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd, TransposeFrom,
    },
    seq_join::{assert_send, seq_join},
    sharding::Sharded,
};

/// This is just a step trait with thread safety bounds. Those make sense
/// on a generic [`Step`] trait so maybe we can change it later.
trait FinalizerStep: Step + Sync + 'static {}
impl<S: Step + Sync + 'static> FinalizerStep for S {}

/// Context to finalize sharded MPC executions. The finalization protocol
/// is very simple - all shards just send data to the leader that performs
/// some sort of aggregation. The aggregation logic can be simple: shuffle
/// just requires bundling all rows together. Or it can be complicated and
/// needing an MPC circuit. Histogram aggregation will need an addition in
/// MPC to properly assemble the final result.
///
/// This trait provides a generic way to write protocols that require
/// shard aggregation step. It only supports ZKP.
trait FinalizerContext: ShardedContext + UpgradableContext {
    type FinalizingContext: ShardedContext + DZKPContext;
    type Step<S: FinalizerStep>;

    fn finalize<S: FinalizerStep, R: ShardAssembledResult<Self::FinalizingContext>>(
        self,
        step: Self::Step<S>,
        inputs: R,
    ) -> impl Future<Output = Result<R, Error>> + Send;
}

/// Trait for results obtained by running sharded MPC protocols. Many shards run MPC
/// executions in parallel and at the end they need to synchronize and agree on final results.
/// The details of that agreement is up to each individual protocol, however the interactions
/// between them is the same:
/// - Once shard completes its computation, it sends its results to the leader shard
/// - When leader completes the MPC part of computation, it blocks awaiting results from all
///   other shards that participate. When all results are received, the leader merges them
///   together to obtain the final result that is later shared with the report collector.
///
/// Based on that interaction, shard final results need to be mergeable and communicated
/// over shard channels as well as they need to have a default value.
trait ShardAssembledResult<C: ShardedContext>: Send + Sized {
    /// Type of messages used to communicate the entire result over the network. Often, shards
    /// hold a collection of shares, so this type will indicate the share type.
    type SingleMessage: Message;

    /// Return empty value that will be used by all shards except the leader,
    /// to set their result of execution.
    fn empty() -> Self;

    /// Merges two assembled results together.
    fn merge<'a>(
        &'a mut self,
        ctx: C,
        record_id: RecordId,
        other: Self,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a
    where
        C: 'a;

    /// Converts this into a form suitable to be sent over the wire
    fn into_messages(self) -> impl ExactSizeIterator<Item = Self::SingleMessage> + Send;

    /// Reverse conversion from the stream of messages back to this type.
    fn from_message_stream<S>(stream: S) -> impl Future<Output = Result<Self, Error>> + Send
    where
        S: Stream<Item = Result<Self::SingleMessage, crate::error::Error>> + Send;
}

impl<'a> FinalizerContext for ShardedMaliciousContext<'a> {
    type FinalizingContext = DZKPUpgradedMaliciousContext<'a, Sharded>;
    type Step<S: FinalizerStep> = MaliciousProtocolSteps<'a, S>;

    #[allow(clippy::manual_async_fn)] // good luck with `Send` is not general enough, clippy
    fn finalize<S: FinalizerStep, R: ShardAssembledResult<Self::FinalizingContext>>(
        self,
        step: Self::Step<S>,
        inputs: R,
    ) -> impl Future<Output = Result<R, Error>> + Send {
        async move {
            // We use a single batch here because the whole assumption of this protocol to be
            // small and simple. If it is not the case, it requires adjustments.
            let validator = self.dzkp_validator(step, usize::MAX);
            let ctx = validator.context();
            let r = semi_honest(ctx, inputs).await?;
            validator.validate().await?;

            Ok(r)
        }
    }
}

impl<'a> FinalizerContext for ShardedSemiHonestContext<'a> {
    type FinalizingContext = DZKPUpgradedSemiHonestContext<'a, Sharded>;
    type Step<S: FinalizerStep> = MaliciousProtocolSteps<'a, S>;

    fn finalize<S: FinalizerStep, R: ShardAssembledResult<Self::FinalizingContext>>(
        self,
        step: Self::Step<S>,
        inputs: R,
    ) -> impl Future<Output = Result<R, Error>> + Send {
        let v = self.dzkp_validator(step, usize::MAX);
        semi_honest(v.context(), inputs)
    }
}

/// This finalizes the MPC execution in sharded context by forwarding the computation results
/// to the leader shard from all follower shards. Leader shard aggregates them and returns it,
/// followers set their result to be empty. This implementation only supports semi-honest
/// security and shouldn't be used directly. Instead [`FinalizerContext`] provides a means
/// to finalize the execution.
/// This is a generic implementation that works for both malicious and semi-honest. For the
/// former, it requires validation phase to be performed after.
async fn semi_honest<C: ShardedContext, R: ShardAssembledResult<C>>(
    ctx: C,
    inputs: R,
) -> Result<R, crate::error::Error> {
    if ctx.is_leader() {
        // leader gets everything from followers
        let final_r = futures::stream::iter(ctx.peer_shards())
            .then(|shard| {
                let stream = ctx.shard_recv_channel::<R::SingleMessage>(shard);
                R::from_message_stream(stream)
            })
            .enumerate()
            .map(|(i, va)| va.map(|v| (v, i)))
            .try_fold(inputs, |mut acc, (r, record_id)| {
                // we merge elements into a single accumulator one by one, thus
                // record count is indeterminate. A better strategy would be to do
                // tree-based merge
                println!("we are in {:?}", ctx.gate());
                let ctx = ctx.set_total_records(TotalRecords::Indeterminate);
                async move {
                    assert_send(acc.merge(ctx, RecordId::from(record_id), r)).await?;
                    Ok(acc)
                }
            })
            .await?;

        Ok(final_r)
    } else {
        // follower just sends its data to the leader
        let shares = inputs.into_messages();
        let sz = shares.len();
        let ctx = ctx.set_total_records(TotalRecords::specified(sz).unwrap_or(TotalRecords::ONE));

        let send_channel = ctx.shard_send_channel::<R::SingleMessage>(ctx.leader());

        seq_join(
            ctx.active_work(),
            futures::stream::iter(shares)
                .enumerate()
                .map(|(i, v)| send_channel.send(RecordId::from(i), v)),
        )
        .try_collect::<()>()
        .await?;

        send_channel.close(RecordId::from(sz)).await;

        Ok(R::empty())
    }
}

/// This type exists to bind [`HV`] and [`B`] together and allow
/// conversions from [`AdditiveShare<HV>`] to [`BitDecomposed<AdditiveShare<Boolean, B>>`]
/// and vice versa. Decomposed view is used to perform additions,
/// share is used to send data to other shards.
#[derive(Debug, Default)]
struct Histogram<HV: BooleanArray, const B: usize>
where
    Boolean: FieldSimd<B>,
{
    values: BitDecomposed<AdditiveShare<Boolean, B>>,
    _marker: PhantomData<HV>,
}

impl<HV: BooleanArray, const B: usize> Histogram<HV, B>
where
    BitDecomposed<AdditiveShare<Boolean, B>>:
        for<'a> TransposeFrom<&'a Vec<AdditiveShare<HV>>, Error = LengthError>,
    Vec<AdditiveShare<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<AdditiveShare<Boolean, B>>, Error = LengthError>,
    Boolean: FieldSimd<B>,
{
    pub fn new(input: &Vec<AdditiveShare<HV>>) -> Result<Self, LengthError> {
        Ok(Self {
            values: BitDecomposed::transposed_from(input)?,
            _marker: PhantomData,
        })
    }

    pub fn compose(&self) -> Vec<AdditiveShare<HV>> {
        if self.values.is_empty() {
            Vec::new()
        } else {
            // unwrap here is safe because we converted values from a vector during
            // initialization, so it must have the value we need
            Vec::transposed_from(&self.values).unwrap()
        }
    }
}

#[cfg(test)]
impl<HV: BooleanArray, const B: usize> crate::test_fixture::Reconstruct<Vec<HV>>
    for [Histogram<HV, B>; 3]
where
    Boolean: FieldSimd<B>,
    BitDecomposed<AdditiveShare<Boolean, B>>:
        for<'a> TransposeFrom<&'a Vec<AdditiveShare<HV>>, Error = LengthError>,
    Vec<AdditiveShare<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<AdditiveShare<Boolean, B>>, Error = LengthError>,
{
    fn reconstruct(&self) -> Vec<HV> {
        let shares = self.each_ref().map(Histogram::compose);
        shares.reconstruct()
    }
}

impl<C: ShardedContext, HV: BooleanArray, const B: usize> ShardAssembledResult<C>
    for Histogram<HV, B>
where
    AdditiveShare<Boolean, B>: BooleanProtocols<C, B>,
    Boolean: FieldSimd<B>,
    // I mean... there must be a less-verbose way to write these bounds
    Vec<AdditiveShare<HV>>:
        for<'a> TransposeFrom<&'a BitDecomposed<AdditiveShare<Boolean, B>>, Error = LengthError>,
    BitDecomposed<AdditiveShare<Boolean, B>>:
        for<'a> TransposeFrom<&'a Vec<AdditiveShare<HV>>, Error = LengthError>,
    <HV as Serializable>::Size: Add<Output: ArrayLength>,
{
    type SingleMessage = AdditiveShare<HV>;

    fn empty() -> Self {
        Self::default()
    }

    #[allow(clippy::manual_async_fn)]
    fn merge<'a>(
        &'a mut self,
        ctx: C,
        record_id: RecordId,
        other: Self,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a
    where
        C: 'a,
    {
        async move {
            // todo: EightBit only works for 256 breakdowns. EightBitStep will panic if we try
            // to add larger values
            self.values =
                integer_sat_add::<_, EightBitStep, B>(ctx, record_id, &self.values, &other.values)
                    .await?;

            Ok(())
        }
    }

    fn into_messages(self) -> impl ExactSizeIterator<Item = Self::SingleMessage> + Send {
        self.compose().into_iter()
    }

    #[allow(clippy::manual_async_fn)]
    fn from_message_stream<S>(stream: S) -> impl Future<Output = Result<Self, Error>> + Send
    where
        S: Stream<Item = Result<Self::SingleMessage, Error>> + Send,
    {
        async move { Ok(Self::new(&stream.try_collect::<Vec<_>>().await?)?) }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::repeat;

    use crate::{
        ff::{boolean_array::BA8, U128Conversions},
        helpers::{in_memory_config::MaliciousHelper, Role},
        protocol::{
            basics::shard_fin::{FinalizerContext, Histogram},
            context::TEST_DZKP_STEPS,
        },
        sharding::ShardIndex,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards},
    };

    /// generate some data to validate the integer addition finalizer
    fn gen<const SHARDS: usize>(values: [BA8; SHARDS]) -> impl Iterator<Item = BA8> + Clone {
        let mut cnt = 0;
        // each shard receive the same value
        std::iter::from_fn(move || {
            cnt += 1;
            Some(values[(cnt - 1) % SHARDS])
        })
    }

    #[test]
    fn semi_honest() {
        run(|| async {
            const SHARDS: usize = 3;
            let world: TestWorld<WithShards<SHARDS>> =
                TestWorld::with_shards(TestWorldConfig::default());

            let input = gen::<SHARDS>([
                BA8::truncate_from(10_u128),
                BA8::truncate_from(21_u128),
                BA8::truncate_from(3_u128),
            ])
            .take(16 * SHARDS);
            let results = world
                .semi_honest(input.clone(), |ctx, input| async move {
                    let input = Histogram::<BA8, 16>::new(&input).unwrap();
                    ctx.finalize(TEST_DZKP_STEPS, input).await.unwrap()
                })
                .await;

            // leader aggregates everything
            let leader_shares = results[0].reconstruct();
            assert_eq!(
                repeat(BA8::truncate_from(34_u128))
                    .take(16)
                    .collect::<Vec<_>>(),
                leader_shares
            );

            // followers have nothing
            let f1 = results[1].reconstruct();
            let f2 = results[2].reconstruct();
            assert_eq!(f1, f2);
            assert_eq!(0, f1.len());
        });
    }

    #[test]
    fn malicious() {
        run(|| async {
            const SHARDS: usize = 3;
            let world: TestWorld<WithShards<SHARDS>> =
                TestWorld::with_shards(TestWorldConfig::default());

            let input = gen::<SHARDS>([
                BA8::truncate_from(1_u128),
                BA8::truncate_from(3_u128),
                BA8::truncate_from(5_u128),
            ])
            .take(16 * SHARDS);
            let results = world
                .malicious(input.clone(), |ctx, input| async move {
                    let input = Histogram::<BA8, 16>::new(&input).unwrap();
                    ctx.finalize(TEST_DZKP_STEPS, input).await.unwrap()
                })
                .await;

            // leader aggregates everything
            let leader_shares = results[0].reconstruct();
            assert_eq!(
                repeat(BA8::truncate_from(9_u128))
                    .take(16)
                    .collect::<Vec<_>>(),
                leader_shares
            );

            // followers have nothing
            let f1 = results[1].reconstruct();
            let f2 = results[2].reconstruct();
            assert_eq!(f1, f2);
            assert_eq!(0, f1.len());
        });
    }

    #[test]
    #[should_panic(expected = "DZKPValidationFailed")]
    fn malicious_attack_resistant() {
        run(|| async {
            const SHARDS: usize = 3;
            let mut config = TestWorldConfig::default();
            config.stream_interceptor =
                MaliciousHelper::new(Role::H2, config.role_assignment(), move |ctx, data| {
                    if ctx
                        .gate
                        .as_ref()
                        .contains(TEST_DZKP_STEPS.protocol.as_ref())
                        && ctx.dest == Role::H1
                        && ctx.shard == Some(ShardIndex::FIRST)
                    {
                        data[0] ^= 1u8;
                    }
                });
            let world: TestWorld<WithShards<SHARDS>> = TestWorld::with_shards(config);

            let input = gen::<SHARDS>([
                BA8::truncate_from(1_u128),
                BA8::truncate_from(3_u128),
                BA8::truncate_from(5_u128),
            ])
            .take(16 * SHARDS);
            world
                .malicious(input, |ctx, input| async move {
                    ctx.finalize(TEST_DZKP_STEPS, Histogram::<BA8, 16>::new(&input).unwrap())
                        .await
                        .unwrap()
                })
                .await;
        });
    }
}
