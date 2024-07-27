use crate::{
    helpers::{
        transport::in_memory::transport::{InMemoryTransport, Setup},
        HelperIdentity,
    },
    sharding::ShardIndex,
    sync::{Arc, Weak},
};

/// Container for shard-to-shard communication channels set up for each helper. Each shard is connected
/// to every other shard within the same helper and these connections are stored here. MPC connections
/// for each individual shard are created and stored inside [`super::InMemoryMpcNetwork`].
///
/// This structure helps to have a single entry point for in-memory runs. Dropping it causes all
/// connections to be destroyed. To obtain a sending end of shard communication channel, use
/// [`transport`] method.
///
/// [`transport`]: InMemoryShardNetwork::transport
pub struct InMemoryShardNetwork {
    pub shard_network: [Box<[Arc<InMemoryTransport<ShardIndex>>]>; 3],
}

impl InMemoryShardNetwork {
    pub fn with_shards<I: Into<ShardIndex>>(shard_count: I) -> Self {
        let shard_count = shard_count.into();
        let shard_network: [_; 3] = HelperIdentity::make_three().map(|h| {
            let mut shard_connections = shard_count.iter().map(Setup::new).collect::<Vec<_>>();
            for i in 0..shard_connections.len() {
                let (lhs, rhs) = shard_connections.split_at_mut(i);
                if let Some((a, _)) = lhs.split_last_mut() {
                    for b in rhs {
                        Setup::connect(a, b);
                    }
                }
            }

            shard_connections
                .into_iter()
                .map(|s| tracing::info_span!("", ?h).in_scope(|| s.start(None)))
                .collect::<Vec<_>>()
                .into()
        });

        Self { shard_network }
    }

    pub fn transport<I: Into<ShardIndex>>(
        &self,
        id: HelperIdentity,
        shard_id: I,
    ) -> Weak<InMemoryTransport<ShardIndex>> {
        Arc::downgrade(&self.shard_network[id][usize::from(shard_id.into())])
    }

    pub fn shard_transports<I: Into<ShardIndex>>(
        &self,
        shard_id: I,
    ) -> [Weak<InMemoryTransport<ShardIndex>>; 3] {
        let shard_id = usize::from(shard_id.into());
        // see #121
        [
            Arc::downgrade(&self.shard_network[0][shard_id]),
            Arc::downgrade(&self.shard_network[1][shard_id]),
            Arc::downgrade(&self.shard_network[2][shard_id]),
        ]
    }

    pub fn reset(&self) {
        for helper in &self.shard_network {
            for shard in helper {
                shard.reset();
            }
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {

    use futures_util::StreamExt;
    use tokio::sync::mpsc;
    use tokio_stream::wrappers::ReceiverStream;

    use crate::{
        helpers::{
            transport::{in_memory::InMemoryShardNetwork, routing::RouteId},
            HelperIdentity, Transport,
        },
        protocol::{Gate, QueryId},
        sharding::ShardIndex,
        test_executor::run,
        test_fixture::logging,
    };

    fn shard_pairs<I: Into<ShardIndex>>(
        shard_count: I,
    ) -> impl Iterator<Item = (ShardIndex, ShardIndex)> {
        let shard_count = shard_count.into();
        shard_count.iter().flat_map(move |a| {
            shard_count
                .iter()
                .filter_map(move |b| (a != b).then_some((a, b)))
        })
    }

    #[test]
    fn shards_talk_to_each_other() {
        logging::setup();
        run(|| async {
            let shard_count = 5;
            let shard_network = InMemoryShardNetwork::with_shards(shard_count);
            let mut sum: u32 = 0;

            for identity in HelperIdentity::make_three() {
                for (a, b) in shard_pairs(shard_count) {
                    let (tx, rx) = mpsc::channel(1);
                    shard_network
                        .transport(identity, a)
                        .send(
                            b,
                            (RouteId::Records, QueryId, Gate::default()),
                            ReceiverStream::new(rx),
                        )
                        .await
                        .unwrap();
                    tx.send(vec![1]).await.unwrap();
                }

                for (a, b) in shard_pairs(shard_count) {
                    sum += shard_network
                        .transport(identity, a)
                        .receive(b, (QueryId, Gate::default()))
                        .into_bytes_stream()
                        .collect::<Vec<_>>()
                        .await
                        .into_iter()
                        .flatten()
                        .map(u32::from)
                        .sum::<u32>();
                }
            }

            // total number of messages sent by each shard: N - 1
            assert_eq!(3 * shard_count * (shard_count - 1), sum);
        });
    }

    #[test]
    fn network_owns_transports() {
        run(|| async {
            let shard_network = InMemoryShardNetwork::with_shards(3);
            let [h1, h2, h3] =
                HelperIdentity::make_three().map(|identity| shard_network.transport(identity, 0));
            drop(shard_network);
            assert!(h1.upgrade().is_none());
            assert!(h2.upgrade().is_none());
            assert!(h3.upgrade().is_none());
        });
    }

    #[test]
    fn reset() {
        async fn test_send(network: &InMemoryShardNetwork) {
            let (_tx, rx) = mpsc::channel(1);
            let src_shard = ShardIndex::FIRST;
            let dst_shard = ShardIndex::from(1);
            network
                .transport(HelperIdentity::ONE, src_shard)
                .send(
                    dst_shard,
                    (RouteId::Records, QueryId, Gate::default()),
                    ReceiverStream::new(rx),
                )
                .await
                .unwrap();
        }

        run(|| async {
            let shard_network = InMemoryShardNetwork::with_shards(2);
            test_send(&shard_network).await;
            shard_network.reset();
            test_send(&shard_network).await;
        });
    }
}
