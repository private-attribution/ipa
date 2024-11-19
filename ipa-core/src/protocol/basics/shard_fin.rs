use std::ops::Add;

use futures::{future, Stream, StreamExt, TryStreamExt};
use generic_array::ArrayLength;

use crate::{
    ff::{boolean_array::BooleanArray, Serializable},
    helpers::{Message, TotalRecords},
    protocol::{context::ShardedContext, RecordId},
    secret_sharing::replicated::semi_honest::AdditiveShare,
    seq_join::seq_join,
};

/// This finalizes the MPC execution in sharded context by forwarding the computation results
/// to the leader shard from all follower shards. Leader shard aggregates them and returns it,
/// followers set their result to be empty.
async fn finalize<C: ShardedContext, R: ShardAssembledResult>(
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
            .try_fold(inputs, |mut acc, r| {
                acc.merge(r);
                future::ok(acc)
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

/// Trait for results obtained by running sharded MPC protocols. Many shards run MPC
/// executions in parallel and at the end they need to synchronize and agree on final results.
/// The details of that agreement is up to each individual protocol, however the interactions
/// between them is the same:
/// - Once shard completes its computation, it sends its results to the leader shard
/// - When leader completes the MPC part of computation, it blocks awaiting results from all
/// other shards that participate. When all results are received, the leader merges them
/// together to obtain the final result that is later shared with the report collector.
///
/// Based on that interaction, shard final results need to be mergeable and communicated
/// over shard channels as well as they need to have a default value.
#[async_trait::async_trait]
trait ShardAssembledResult: Sized {
    /// Type of messages used to communicate the entire result over the network. Often, shards
    /// hold a collection of shares, so this type will indicate the share type.
    type SingleMessage: Message;

    /// Return empty value that will be used by all shards except the leader,
    /// to set their result of execution.
    fn empty() -> Self;

    /// Merges two assembled results together.
    fn merge(&mut self, other: Self);

    /// Converts this into a form suitable to be sent over the wire
    fn into_messages(self) -> impl ExactSizeIterator<Item = Self::SingleMessage> + Send;

    /// Reverse conversion from the stream of messages back to this type.
    async fn from_message_stream<
        S: Stream<Item = Result<Self::SingleMessage, crate::error::Error>> + Send,
    >(
        stream: S,
    ) -> Result<Self, crate::error::Error>;
}

#[async_trait::async_trait]
impl<HV: BooleanArray> ShardAssembledResult for Vec<AdditiveShare<HV>>
where
    <HV as Serializable>::Size: Add<Output: ArrayLength>,
{
    type SingleMessage = AdditiveShare<HV>;

    fn empty() -> Self {
        Vec::new()
    }

    fn merge(&mut self, other: Self) {
        // this merges two histograms together by adding them up
        for (a, b) in self.iter_mut().zip(other) {
            *a += b;
        }
    }

    fn into_messages(self) -> impl ExactSizeIterator<Item = Self::SingleMessage> + Send {
        self.into_iter()
    }

    async fn from_message_stream<
        S: Stream<Item = Result<Self::SingleMessage, crate::error::Error>> + Send,
    >(
        stream: S,
    ) -> Result<Self, crate::error::Error> {
        stream.try_collect::<Vec<_>>().await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ff::boolean_array::BA64,
        protocol::basics::shard_fin::finalize,
        secret_sharing::SharedValue,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards},
    };

    #[test]
    fn shards_set_result() {
        run(|| async {
            let world: TestWorld<WithShards<3>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let input = vec![BA64::ZERO, BA64::ZERO, BA64::ZERO];
            let results = world
                .semi_honest(input.into_iter(), |ctx, input| async move {
                    assert_eq!(1, input.len());
                    finalize(ctx, input).await.unwrap()
                })
                .await;

            // leader aggregates everything
            let leader_shares = results[0].reconstruct();
            assert_eq!(vec![BA64::ZERO], leader_shares);

            // followers have nothing
            let f1 = results[1].reconstruct();
            let f2 = results[2].reconstruct();
            assert_eq!(f1, f2);
            assert_eq!(0, f1.len());
        });
    }
}
