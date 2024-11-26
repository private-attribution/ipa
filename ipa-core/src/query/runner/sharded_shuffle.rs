use std::future::Future;

use futures::{FutureExt, Stream};
use futures_util::TryStreamExt;
use ipa_step::StepNarrow;

use crate::{
    error::Error,
    ff::boolean_array::BA64,
    helpers::{setup_cross_shard_prss, BodyStream, Gateway, SingleRecordStream},
    protocol::{
        basics::{FinalizerContext, ShardAssembledResult},
        context::{Context, MaliciousProtocolSteps, ShardedContext, ShardedSemiHonestContext},
        ipa_prf::shuffle::ShardedShuffle,
        prss::Endpoint as PrssEndpoint,
        step::{ProtocolStep, TestShardedShuffleStep},
        Gate, RecordId,
    },
    query::runner::QueryResult,
    secret_sharing::replicated::semi_honest::AdditiveShare,
    sharding::{ShardConfiguration, Sharded},
    sync::Arc,
};

/// This holds the result of executing the test version of
/// the sharded shuffle protocol.
struct ShardedShuffleOutput(Vec<AdditiveShare<BA64>>);

/// Finalization protocol for sharded shuffle. All shares sent from followers
/// to the leader shard get bundled together into a single vector.
impl<C: ShardedContext> ShardAssembledResult<C> for ShardedShuffleOutput {
    type SingleMessage = AdditiveShare<BA64>;

    fn empty() -> Self {
        Self(Vec::new())
    }

    fn merge<'a>(
        &'a mut self,
        _ctx: C,
        _record_id: RecordId,
        other: Self,
    ) -> impl Future<Output = Result<(), Error>> + Send + 'a
    where
        C: 'a,
    {
        self.0.extend(other.0);
        futures::future::ok(())
    }

    fn into_messages(self) -> impl ExactSizeIterator<Item = Self::SingleMessage> + Send {
        self.0.into_iter()
    }

    fn from_message_stream<S>(stream: S) -> impl Future<Output = Result<Self, Error>> + Send
    where
        S: Stream<Item = Result<Self::SingleMessage, Error>> + Send,
    {
        stream.try_collect::<Vec<_>>().map(|v| v.map(Self))
    }
}

/// This executes the sharded shuffle protocol that consists of only one step:
/// permute the private inputs using a permutation that is not known to any helper
/// and client.
pub async fn execute_sharded_shuffle<'a>(
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    input: BodyStream,
) -> QueryResult {
    let gate = Gate::default().narrow(&ProtocolStep::CrossShardPrss);
    let cross_shard_prss =
        setup_cross_shard_prss(gateway, &gate, prss.indexed(&gate), gateway).await?;
    let ctx = ShardedSemiHonestContext::new_sharded(
        prss,
        gateway,
        Sharded {
            shard_id: gateway.shard_id(),
            shard_count: gateway.shard_count(),
            prss: Arc::new(cross_shard_prss),
        },
    )
    .narrow(&ProtocolStep::ShardedShuffle);

    Ok(Box::new(execute(ctx, input).await?))
}

#[tracing::instrument("sharded_shuffle", skip_all)]
pub async fn execute<C>(ctx: C, input_stream: BodyStream) -> Result<Vec<AdditiveShare<BA64>>, Error>
where
    C: ShardedContext + ShardedShuffle + FinalizerContext,
{
    let input = SingleRecordStream::<AdditiveShare<BA64>, _>::new(input_stream)
        .try_collect::<Vec<_>>()
        .await?;
    let shuffle_ctx = ctx.narrow(&TestShardedShuffleStep::Shuffle);

    let output = ShardedShuffleOutput(shuffle_ctx.sharded_shuffle(input).await?);

    Ok(ctx
        .finalize(
            MaliciousProtocolSteps {
                protocol: &TestShardedShuffleStep::Finalize,
                validate: &TestShardedShuffleStep::FinalizeValidate,
            },
            output,
        )
        .await?
        .0)
}

#[cfg(all(test, unit_test))]
mod tests {
    use futures_util::future::try_join_all;
    use generic_array::GenericArray;
    use typenum::Unsigned;

    use crate::{
        ff::{boolean_array::BA64, Serializable, U128Conversions},
        query::runner::sharded_shuffle::execute,
        secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
        test_executor::run,
        test_fixture::{try_join3_array, Reconstruct, TestWorld, TestWorldConfig, WithShards},
        utils::array::zip3,
    };

    #[test]
    fn basic() {
        run(|| async {
            const SHARDS: usize = 20;
            let world: TestWorld<WithShards<3>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let contexts = world.contexts();
            let input = (0..20_u128).map(BA64::truncate_from).collect::<Vec<_>>();

            #[allow(clippy::redundant_closure_for_method_calls)]
            let shard_shares: [Vec<Vec<AdditiveShare<BA64>>>; 3] =
                input.clone().into_iter().share().map(|helper_shares| {
                    helper_shares
                        .chunks(SHARDS / 3)
                        .map(|v| v.to_vec())
                        .collect()
                });

            let result =
                try_join3_array(zip3(contexts, shard_shares).map(|(h_contexts, h_shares)| {
                    try_join_all(
                        h_contexts
                            .into_iter()
                            .zip(h_shares)
                            .map(|(ctx, shard_shares)| {
                                let shard_stream = shard_shares
                                    .into_iter()
                                    .flat_map(|share| {
                                        const SIZE: usize =
                                            <AdditiveShare<BA64> as Serializable>::Size::USIZE;
                                        let mut slice = [0_u8; SIZE];
                                        share.serialize(GenericArray::from_mut_slice(&mut slice));
                                        slice
                                    })
                                    .collect::<Vec<_>>()
                                    .into();

                                execute(ctx, shard_stream)
                            }),
                    )
                }))
                .await
                .unwrap()
                .map(|v| v.into_iter().flatten().collect::<Vec<_>>())
                .reconstruct();

            // 1/20! probability of this permutation to be the same
            assert_ne!(input, result);
        });
    }
}
