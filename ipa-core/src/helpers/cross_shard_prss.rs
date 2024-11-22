use futures::{stream::FuturesUnordered, TryStreamExt};

use crate::{
    helpers::{buffers::EndOfStreamError, ChannelId, Error, Gateway, TotalRecords},
    protocol::{
        prss::{Endpoint as PrssEndpoint, Seed, SeededEndpointSetup, SharedRandomness},
        Gate, RecordId,
    },
    sharding::ShardConfiguration,
};

/// This routine sets up cross-shard coordinated randomness. Each
/// shard has access to the same PRSS instance as all others on the same helper.
/// The PRSS instance is seeded by the leader shard, and seed is distributed
/// to other instances. As with regular PRSS, there are two random generators:
/// one is shared with helper on the left and another one with the right helper.
///
/// ## Errors
/// If shard communication channels fail
#[allow(dead_code)] // until this is used in real sharded protocol
pub async fn gen_and_distribute<R: SharedRandomness, C: ShardConfiguration>(
    gateway: &Gateway,
    gate: &Gate,
    prss: R,
    shard_config: C,
) -> Result<PrssEndpoint, crate::error::Error> {
    let endpoint = if shard_config.is_leader() {
        // Generate seeds
        let setup: SeededEndpointSetup = prss.generate(RecordId::FIRST);

        // Distribute them across all shards
        shard_config
            .peer_shards()
            .map(|shard| {
                let channel = ChannelId::new(shard, gate.clone());
                let sender = gateway.get_shard_sender(&channel, TotalRecords::ONE);
                let (l_seed, r_seed) = (setup.left_seed().clone(), setup.right_seed().clone());
                async move { sender.send(RecordId::FIRST, (l_seed, r_seed)).await }
            })
            .collect::<FuturesUnordered<_>>()
            .try_collect::<()>()
            .await?;

        // finish the setup
        setup.setup()
    } else {
        // Receive seeds from the leader.
        let channel_id = ChannelId::new(shard_config.leader(), gate.clone());
        let (l_seed, r_seed): (_, Seed) = gateway
            .get_shard_receiver(&channel_id)
            .try_next()
            .await?
            .ok_or_else(|| Error::EndOfStream {
                channel_id,
                inner: EndOfStreamError(RecordId::FIRST),
            })?;

        SeededEndpointSetup::from_seeds(l_seed, r_seed).setup()
    };

    Ok(endpoint)
}

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        ff::boolean_array::BA64,
        helpers::cross_shard_prss::gen_and_distribute,
        protocol::{context::Context, prss::SharedRandomness, Gate, RecordId},
        secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
        sharding::ShardConfiguration,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards},
    };

    #[test]
    fn shard_setup() {
        run(|| async {
            let world: TestWorld<WithShards<4>> =
                TestWorld::with_shards(TestWorldConfig::default());
            let values = world
                .semi_honest(std::iter::empty::<BA64>(), |ctx, _| {
                    let world = &world;
                    async move {
                        let gateway = world.gateway(ctx.role(), ctx.shard_id());
                        let shard_prss =
                            gen_and_distribute(gateway, &Gate::default(), ctx.prss(), ctx.clone())
                                .await
                                .unwrap();

                        let share: AdditiveShare<BA64> = shard_prss
                            .indexed(&Gate::default())
                            .generate(RecordId::FIRST);
                        share
                    }
                })
                .await;

            let mut v = BA64::ZERO; // assumes the number of shards is even
            for shares in values {
                v += shares.reconstruct();
            }

            assert_eq!(BA64::ZERO, v);
        });
    }
}
