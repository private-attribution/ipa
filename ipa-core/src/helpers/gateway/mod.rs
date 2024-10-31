mod receive;
mod send;
#[cfg(feature = "stall-detection")]
pub(super) mod stall_detection;
mod transport;

use std::{
    cmp::{max, min},
    num::NonZeroUsize,
};

pub(super) use receive::{MpcReceivingEnd, ShardReceivingEnd};
pub(super) use send::SendingEnd;
#[cfg(feature = "stall-detection")]
pub(super) use stall_detection::InstrumentedGateway;
pub use transport::RoleResolvingTransport;

use crate::{
    helpers::{
        buffers::UnorderedReceiver,
        gateway::{
            receive::{GatewayReceivers, ShardReceiveStream, UR},
            send::GatewaySenders,
            transport::Transports,
        },
        query::QueryConfig,
        HelperChannelId, LogErrors, Message, MpcMessage, RecordsStream, Role, RoleAssignment,
        ShardChannelId, TotalRecords, Transport,
    },
    protocol::QueryId,
    sharding::ShardIndex,
    sync::{Arc, Mutex},
    utils::NonZeroU32PowerOfTwo,
};

/// Alias for the currently configured transport.
///
/// To avoid proliferation of type parameters, most code references this concrete type alias, rather
/// than a type parameter `T: Transport`.
#[cfg(feature = "in-memory-infra")]
type TransportImpl<I> = super::transport::InMemoryTransport<I>;
#[cfg(feature = "in-memory-infra")]
pub type MpcTransportImpl = TransportImpl<crate::helpers::HelperIdentity>;
#[cfg(feature = "in-memory-infra")]
pub type ShardTransportImpl = TransportImpl<ShardIndex>;

#[cfg(feature = "real-world-infra")]
pub type MpcTransportImpl = crate::net::MpcHttpTransport;
#[cfg(feature = "real-world-infra")]
pub type ShardTransportImpl = crate::net::ShardHttpTransport;

pub type MpcTransportError = <MpcTransportImpl as Transport>::Error;

/// Gateway into IPA Network infrastructure. It allows helpers send and receive messages.
pub struct Gateway {
    config: GatewayConfig,
    transports: Transports<RoleResolvingTransport, ShardTransportImpl>,
    query_id: QueryId,
    #[cfg(feature = "stall-detection")]
    inner: crate::sync::Arc<State>,
    #[cfg(not(feature = "stall-detection"))]
    inner: State,
}

#[derive(Default)]
pub struct State {
    mpc_senders: GatewaySenders<Role>,
    mpc_receivers: GatewayReceivers<Role, UR>,
    shard_senders: GatewaySenders<ShardIndex>,
    shard_receivers: GatewayReceivers<ShardIndex, ShardReceiveStream>,
}

#[derive(Clone, Copy, Debug)]
pub struct GatewayConfig {
    /// The number of items that can be active at the one time.
    /// This is used to determine the size of sending and receiving buffers.
    pub active: NonZeroU32PowerOfTwo,

    /// Number of bytes packed and sent together in one batch down to the network layer. This
    /// shouldn't be too small to keep the network throughput, but setting it large enough may
    /// increase latency due to TCP/HTTP active window adjusting.
    /// A rule of thumb is that this should get as close to network packet size as possible.
    ///
    /// This will be set for all channels and because they send records of different side, the actual
    /// payload may not be exactly this, but it will be the closest multiple of record size smaller than
    /// or equal to number. For alignment reasons, this multiple will be a power of two, otherwise
    /// a deadlock is possible. See ipa/#1300 for details how it can happen.
    ///
    /// For instance, having 14 bytes records and batch size of 4096 will result in
    /// 3584 bytes being sent in a batch (`2^8 * 14 < 4096, 2^9 * 14 > 4096`).
    ///
    /// The consequence is that HTTP buffer size may not be perfectly aligned with the target.
    /// As long as we use TCP it does not matter, but if we want to switch to UDP and have
    /// precise control over the size of chunk sent, we should tune the buffer size at the
    /// HTTP layer instead (using Hyper/H3 API or something like that). If we do this, then
    /// read size becomes obsolete and should be removed in favor of flushing the entire
    /// buffer chunks from the application layer down to HTTP and let network to figure out
    /// the best way to slice this data before sending it to a peer.
    pub read_size: NonZeroUsize,

    /// Time to wait before checking gateway progress. If no progress has been made between
    /// checks, the gateway is considered to be stalled and will create a report with outstanding
    /// send/receive requests
    #[cfg(feature = "stall-detection")]
    pub progress_check_interval: std::time::Duration,
}

impl Gateway {
    #[must_use]
    pub fn new(
        query_id: QueryId,
        config: GatewayConfig,
        roles: RoleAssignment,
        mpc_transport: MpcTransportImpl,
        shard_transport: ShardTransportImpl,
    ) -> Self {
        tracing::debug!("active_work = {}", config.active);
        #[allow(clippy::useless_conversion)] // not useless in stall-detection build
        Self {
            query_id,
            config,
            transports: Transports {
                mpc: RoleResolvingTransport {
                    roles,
                    inner: mpc_transport,
                },
                shard: shard_transport,
            },
            inner: State::default().into(),
        }
    }

    #[must_use]
    pub fn role(&self) -> Role {
        self.transports.mpc.identity()
    }

    #[must_use]
    pub fn config(&self) -> &GatewayConfig {
        &self.config
    }

    /// Returns a sender suitable for sending data between MPC helpers. The data must be approved
    /// for sending by implementing [`MpcMessage`] trait.
    ///
    /// Do not remove the test below, it verifies that we don't allow raw sharings to be sent
    /// between MPC helpers without using secure reveal.
    ///
    /// ```compile_fail
    /// use ipa_core::helpers::Gateway;
    /// use ipa_core::secret_sharing::replicated::semi_honest::AdditiveShare;
    /// use ipa_core::ff::Fp32BitPrime;
    ///
    /// let gateway: Gateway = todo!();
    /// let mpc_channel = gateway.get_mpc_sender::<AdditiveShare<Fp32BitPrime>>(todo!(), todo!());
    /// ```
    ///
    /// ## Panics
    /// If there is a failure connecting via HTTP
    #[must_use]
    pub fn get_mpc_sender<M: MpcMessage>(
        &self,
        channel_id: &HelperChannelId,
        total_records: TotalRecords,
        active_work: NonZeroU32PowerOfTwo,
    ) -> send::SendingEnd<Role, M> {
        let transport = &self.transports.mpc;
        let channel = self.inner.mpc_senders.get::<M, _>(
            channel_id,
            transport,
            // we override the active work provided in config if caller
            // wants to use a different value.
            self.config.set_active_work(active_work),
            self.query_id,
            total_records,
        );

        send::SendingEnd::new(channel, transport.identity())
    }

    /// Returns a sender for shard-to-shard traffic. This sender is more relaxed compared to one
    /// returned by [`Self::get_mpc_sender`] as it allows anything that can be serialized into bytes
    /// to be sent out. MPC sender needs to be more careful about it and not to allow sending sensitive
    /// information to be accidentally revealed.
    /// An example of such sensitive data could be secret sharings - it is perfectly fine to send them
    /// between shards as they are known to each helper anyway. Sending them across MPC helper boundary
    /// could lead to information reveal.
    pub fn get_shard_sender<M: Message>(
        &self,
        channel_id: &ShardChannelId,
        total_records: TotalRecords,
    ) -> send::SendingEnd<ShardIndex, M> {
        let transport = &self.transports.shard;
        let channel = self.inner.shard_senders.get::<M, _>(
            channel_id,
            transport,
            self.config,
            self.query_id,
            total_records,
        );

        send::SendingEnd::new(channel, transport.identity())
    }

    #[must_use]
    pub fn get_mpc_receiver<M: MpcMessage>(
        &self,
        channel_id: &HelperChannelId,
    ) -> receive::MpcReceivingEnd<M> {
        receive::MpcReceivingEnd::new(
            channel_id.clone(),
            self.inner.mpc_receivers.get_or_create(channel_id, || {
                UnorderedReceiver::new(
                    Box::pin(LogErrors::new(self.transports.mpc.receive(
                        channel_id.peer,
                        (self.query_id, channel_id.gate.clone()),
                    ))),
                    self.config.active_work(),
                )
            }),
        )
    }

    /// Requests a stream of records to be received from the given shard. In contrast with
    /// [`Self::get_mpc_receiver`] stream, items in this stream are available in FIFO order only.
    pub fn get_shard_receiver<M: Message>(
        &self,
        channel_id: &ShardChannelId,
    ) -> receive::ShardReceivingEnd<M> {
        let mut called_before = true;
        let rx = self.inner.shard_receivers.get_or_create(channel_id, || {
            called_before = false;
            ShardReceiveStream(Arc::new(Mutex::new(
                self.transports
                    .shard
                    .receive(channel_id.peer, (self.query_id, channel_id.gate.clone())),
            )))
        });

        assert!(
            !called_before,
            "Shard receiver {channel_id:?} can only be created once"
        );

        receive::ShardReceivingEnd {
            channel_id: channel_id.clone(),
            rx: RecordsStream::new(rx),
        }
    }
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            active: 32768.try_into().unwrap(),
            read_size: 2048.try_into().unwrap(),
            // In-memory tests are fast, so progress check intervals can be lower.
            // Real world scenarios currently over-report stalls because of inefficiencies inside
            // infrastructure and actual networking issues. This check is only valuable to report
            // bugs, so keeping it large enough to avoid false positives.
            #[cfg(feature = "stall-detection")]
            progress_check_interval: std::time::Duration::from_secs(if cfg!(test) {
                5
            } else {
                30
            }),
        }
    }
}

impl GatewayConfig {
    /// The configured amount of active work.
    #[must_use]
    pub fn active_work(&self) -> NonZeroUsize {
        self.active.to_non_zero_usize()
    }

    #[must_use]
    pub fn active_work_as_power_of_two(&self) -> NonZeroU32PowerOfTwo {
        self.active
    }

    /// # Panics
    /// If 2 == 0.
    pub fn set_active_work_from_query_config(&mut self, value: &QueryConfig) {
        // Minimum size for active work is 2 because:
        // * `UnorderedReceiver` wants capacity to be greater than 1
        // * 1 is better represented by not using seq_join and/or indeterminate total records
        let active = max(
            2,
            min(
                Self::default().active.get(),
                // We limit active work to the input size because our CI is too slow for
                // very large active work sizes. Some protocols may want to change this,
                // if their fanout factor per input row is greater than 1. We don't have
                // capabilities (see #ipa/1171) to allow that currently.
                usize::from(value.size),
            ),
        )
        .next_power_of_two();
        // we set active to be at least 2, so unwrap is fine.
        self.active = NonZeroU32PowerOfTwo::try_from(active).unwrap();
    }

    /// Creates a new configuration by overriding the value of active work.
    #[must_use]
    pub fn set_active_work(&self, active_work: NonZeroU32PowerOfTwo) -> Self {
        Self {
            active: active_work,
            ..*self
        }
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{
        iter::{repeat, zip},
        sync::Arc,
    };

    use futures::{
        future::{join, try_join, try_join_all},
        stream,
        stream::StreamExt,
    };
    use proptest::proptest;
    use tokio::sync::Barrier;

    use crate::{
        ff::{
            boolean_array::{BA20, BA256, BA3, BA4, BA5, BA6, BA7, BA8},
            FieldType, Fp31, Fp32BitPrime, Gf2, U128Conversions,
        },
        helpers::{
            gateway::QueryConfig,
            query::{QuerySize, QueryType},
            ChannelId, Direction, GatewayConfig, MpcMessage, MpcReceivingEnd, Role, SendingEnd,
            TotalRecords,
        },
        protocol::{
            context::{Context, ShardedContext},
            Gate, RecordId,
        },
        secret_sharing::{
            replicated::semi_honest::AdditiveShare, SharedValue, SharedValueArray, StdArray,
        },
        seq_join::seq_join,
        sharding::ShardConfiguration,
        test_executor::run,
        test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig, WithShards},
        utils::NonZeroU32PowerOfTwo,
    };

    /// Verifies that [`Gateway`] send buffer capacity is adjusted to the message size.
    /// IPA protocol opens many channels to send values from different fields, while message size
    /// is set per channel, it does not have to be the same across multiple send channels.
    ///
    /// Gateway must be able to deal with it.
    #[tokio::test]
    async fn can_handle_heterogeneous_channels() {
        async fn send<V: MpcMessage + U128Conversions>(channel: &SendingEnd<Role, V>, i: usize) {
            channel
                .send(i.into(), V::truncate_from(u128::try_from(i).unwrap()))
                .await
                .unwrap();
        }

        let config = TestWorldConfig {
            gateway_config: GatewayConfig {
                active: 2.try_into().unwrap(),
                ..Default::default()
            },
            ..Default::default()
        };

        let world = TestWorld::new_with(config);
        world
            .semi_honest((), |ctx, ()| async move {
                let fp2_ctx = ctx.narrow("fp2").set_total_records(100);
                let fp32_ctx = ctx.narrow("fp32").set_total_records(100);
                let role = ctx.role();

                let fp2_channel = fp2_ctx.send_channel::<Gf2>(role.peer(Direction::Right));
                let fp32_channel =
                    fp32_ctx.send_channel::<Fp32BitPrime>(role.peer(Direction::Right));

                // joins must complete, despite us not closing the send channel.
                // fp2 channel byte capacity must be set to 2 bytes, fp32 channel can store 8 bytes.
                join(send(&fp2_channel, 0), send(&fp2_channel, 1)).await;
                join(send(&fp32_channel, 0), send(&fp32_channel, 1)).await;
            })
            .await;
    }

    #[tokio::test]
    pub async fn handles_reordering() {
        let config = TestWorldConfig {
            gateway_config: GatewayConfig {
                active: 2.try_into().unwrap(),
                ..Default::default()
            },
            ..TestWorldConfig::default()
        };
        let world = Box::leak(Box::new(TestWorld::new_with(config)));
        let world_ptr = world as *mut _;
        let contexts = world.contexts();
        let sender_ctx = contexts[0].narrow("reordering-test").set_total_records(2);
        let recv_ctx = contexts[1].narrow("reordering-test").set_total_records(2);

        // send record 1 first and wait for confirmation before sending record 0.
        // when gateway received record 0 it triggers flush so it must make sure record 1 is also
        // sent (same batch or different does not matter here)
        let spawned = tokio::spawn(async move {
            let channel = sender_ctx.send_channel(Role::H2);
            try_join(
                channel.send(RecordId::from(1), Fp31::truncate_from(1_u128)),
                channel.send(RecordId::from(0), Fp31::truncate_from(0_u128)),
            )
            .await
            .unwrap();
        });

        let recv_channel = recv_ctx.recv_channel::<Fp31>(Role::H1);
        let result = try_join(
            recv_channel.receive(RecordId::from(1)),
            recv_channel.receive(RecordId::from(0)),
        )
        .await
        .unwrap();

        assert_eq!(
            (Fp31::truncate_from(1u128), Fp31::truncate_from(0u128)),
            result
        );
        spawned.await.unwrap();
        let _world = unsafe { Box::from_raw(world_ptr) };
    }

    /// this test requires quite a few threads to simulate send contention and will panic if
    /// there is more than one sender channel created per step.
    #[tokio::test(flavor = "multi_thread", worker_threads = 20)]
    pub async fn send_contention() {
        let (world, world_ptr) = make_world();

        try_join_all(world.contexts().map(|ctx| {
            tokio::spawn(async move {
                const TOTAL_RECORDS: usize = 10;
                let ctx = ctx
                    .narrow("send_contention")
                    .set_total_records(TOTAL_RECORDS);

                let receive_handle = tokio::spawn({
                    let ctx = ctx.clone();
                    async move {
                        for record in 0..TOTAL_RECORDS {
                            let v = Fp31::truncate_from(u128::try_from(record).unwrap());
                            let r = ctx
                                .recv_channel::<Fp31>(ctx.role().peer(Direction::Left))
                                .receive(record.into())
                                .await
                                .unwrap();

                            assert_eq!(v, r, "Bad value for record {record}");
                        }
                    }
                });

                try_join_all(zip(0..TOTAL_RECORDS, repeat(ctx)).map(|(record, ctx)| {
                    tokio::spawn(async move {
                        let r = Fp31::truncate_from(u128::try_from(record).unwrap());
                        ctx.send_channel(ctx.role().peer(Direction::Right))
                            .send(RecordId::from(record), r)
                            .await
                            .unwrap();
                    })
                }))
                .await
                .unwrap();

                receive_handle.await.unwrap();
            })
        }))
        .await
        .unwrap();

        let _world = unsafe { Box::from_raw(world_ptr) };
    }

    /// This test should hang if receiver channel is not created atomically. It may occasionally
    /// pass, but it will not give false negatives.
    #[tokio::test(flavor = "multi_thread", worker_threads = 20)]
    pub async fn receive_contention() {
        let (world, world_ptr) = make_world();
        let contexts = world.contexts();

        try_join_all(contexts.map(|ctx| {
            tokio::spawn(async move {
                const TOTAL_RECORDS: u32 = 20;
                let ctx = ctx
                    .narrow("receive_contention")
                    .set_total_records(usize::try_from(TOTAL_RECORDS).unwrap());

                tokio::spawn({
                    let ctx = ctx.clone();
                    async move {
                        for record in 0..TOTAL_RECORDS {
                            ctx.send_channel(ctx.role().peer(Direction::Right))
                                .send(RecordId::from(record), Fp31::truncate_from(record))
                                .await
                                .unwrap();
                        }
                    }
                });

                try_join_all((0..TOTAL_RECORDS).zip(repeat(ctx)).map(|(record, ctx)| {
                    tokio::spawn(async move {
                        let r = ctx
                            .recv_channel::<Fp31>(ctx.role().peer(Direction::Left))
                            .receive(RecordId::from(record))
                            .await
                            .unwrap();
                        assert_eq!(
                            Fp31::truncate_from(record),
                            r,
                            "received bad value for record {record}"
                        );
                    })
                }))
                .await
                .unwrap();
            })
        }))
        .await
        .unwrap();

        let _world = unsafe { Box::from_raw(world_ptr) };
    }

    #[test]
    fn shards() {
        run(|| async move {
            let world = TestWorld::<WithShards<2>>::with_shards(TestWorldConfig::default());
            shard_comms_test(&world).await;
        });
    }

    #[test]
    #[should_panic(
        expected = "Shard receiver channel[ShardIndex(1),\"protocol/iter000\"] can only be created once"
    )]
    fn shards_receive_twice() {
        run(|| async move {
            let world = TestWorld::<WithShards<2>>::with_shards(TestWorldConfig::default());
            world
                .semi_honest(Vec::<()>::new().into_iter(), |ctx, _| async move {
                    let peer = ctx.peer_shards().next().unwrap();
                    let recv1 = ctx.shard_recv_channel::<BA3>(peer);
                    let recv2 = ctx.shard_recv_channel::<BA3>(peer);
                    drop(recv1);
                    drop(recv2);
                })
                .await;
        });
    }

    #[test]
    fn custom_active_work() {
        run(|| async move {
            let world = TestWorld::new_with(TestWorldConfig {
                gateway_config: GatewayConfig {
                    active: 8.try_into().unwrap(),
                    ..Default::default()
                },
                ..Default::default()
            });
            let new_active_work = NonZeroU32PowerOfTwo::try_from(4).unwrap();
            assert!(
                new_active_work
                    < world
                        .gateway(Role::H1)
                        .config()
                        .active_work_as_power_of_two()
            );
            let sender = world.gateway(Role::H1).get_mpc_sender::<BA3>(
                &ChannelId::new(Role::H2, Gate::default()),
                TotalRecords::specified(15).unwrap(),
                new_active_work,
            );
            try_join_all(
                (0..new_active_work.get())
                    .map(|record_id| sender.send(record_id.into(), BA3::ZERO)),
            )
            .await
            .unwrap();
            let recv = world.gateway(Role::H2).get_mpc_receiver::<BA3>(&ChannelId {
                peer: Role::H1,
                gate: Gate::default(),
            });
            // this will hang if the original active work is used
            try_join_all(
                (0..new_active_work.get()).map(|record_id| recv.receive(record_id.into())),
            )
            .await
            .unwrap();
        });
    }

    macro_rules! send_recv_test {
        (
            message: $message:expr,
            read_size: $read_size:expr,
            active_work: $active_work:expr,
            total_records: $total_records:expr,
            $test_fn: ident
        ) => {
            #[test]
            fn $test_fn() {
                run(|| async {
                    send_recv($read_size, $active_work, $total_records, $message).await;
                });
            }
        };
    }

    send_recv_test! {
        message: BA20::ZERO,
        read_size: 5,
        active_work: 8,
        total_records: 25,
        test_ba20_5_10_25
    }

    send_recv_test! {
        message: StdArray::<BA256, 16>::ZERO_ARRAY,
        read_size: 2048,
        active_work: 16,
        total_records: 43,
        test_ba256_by_16_2048_10_43
    }

    send_recv_test! {
        message: StdArray::<BA8, 16>::ZERO_ARRAY,
        read_size: 2048,
        active_work: 32,
        total_records: 50,
        test_ba8_by_16_2048_37_50
    }

    proptest! {
        #[test]
        fn send_recv_randomized(
            total_records in 1_usize..500,
            active in 2_usize..1000,
            read_size in (1_usize..32768),
            record_size in 1_usize..=8,
        ) {
            let active = active.next_power_of_two();
            run(move || async move {
                match record_size {
                    1 => send_recv(read_size, active, total_records, StdArray::<BA8, 32>::ZERO_ARRAY).await,
                    2 => send_recv(read_size, active, total_records, StdArray::<BA8, 64>::ZERO_ARRAY).await,
                    3 => send_recv(read_size, active, total_records, BA3::ZERO).await,
                    4 => send_recv(read_size, active, total_records, BA4::ZERO).await,
                    5 => send_recv(read_size, active, total_records, BA5::ZERO).await,
                    6 => send_recv(read_size, active, total_records, BA6::ZERO).await,
                    7 => send_recv(read_size, active, total_records, BA7::ZERO).await,
                    8 => send_recv(read_size, active, total_records, StdArray::<BA256, 16>::ZERO_ARRAY).await,
                    _ => unreachable!(),
                }
            });
        }
    }

    /// ensures when active work is set from query input, it is always a power of two
    #[test]
    fn gateway_config_active_work_power_of_two() {
        let mut config = GatewayConfig {
            active: 2.try_into().unwrap(),
            ..Default::default()
        };
        config.set_active_work_from_query_config(&QueryConfig {
            size: QuerySize::try_from(5).unwrap(),
            field_type: FieldType::Fp31,
            query_type: QueryType::TestAddInPrimeField,
        });
        assert_eq!(8, config.active_work().get());
    }

    async fn shard_comms_test(test_world: &TestWorld<WithShards<2>>) {
        let input = vec![BA3::truncate_from(0_u32), BA3::truncate_from(1_u32)];

        let r = test_world
            .semi_honest(input.clone().into_iter(), |ctx, input| async move {
                let ctx = ctx.set_total_records(input.len());
                // Swap shares between shards, works only for 2 shards.
                let peer = ctx.peer_shards().next().unwrap();
                for (record_id, item) in input.into_iter().enumerate() {
                    ctx.shard_send_channel(peer)
                        .send(record_id.into(), item)
                        .await
                        .unwrap();
                }

                let mut r = Vec::<AdditiveShare<BA3>>::new();
                let mut recv_channel = ctx.shard_recv_channel(peer);
                while let Some(v) = recv_channel.next().await {
                    r.push(v.unwrap());
                }

                r
            })
            .await
            .into_iter()
            .flat_map(|v| v.reconstruct())
            .collect::<Vec<_>>();

        let reverse_input = input.into_iter().rev().collect::<Vec<_>>();
        assert_eq!(reverse_input, r);
    }

    fn make_world() -> (&'static TestWorld, *mut TestWorld) {
        let world = Box::leak(Box::<TestWorld>::default());
        let world_ptr = world as *mut _;
        (world, world_ptr)
    }

    /// This serves the purpose of randomized testing of our send channels by providing
    /// variable sizes for read size, active work and record size
    async fn send_recv<M>(read_size: usize, active_work: usize, total_records: usize, sample: M)
    where
        M: MpcMessage + Clone + PartialEq,
    {
        fn duplex_channel<M: MpcMessage>(
            world: &TestWorld,
            left: Role,
            right: Role,
            total_records: usize,
            active_work: usize,
        ) -> (SendingEnd<Role, M>, MpcReceivingEnd<M>) {
            (
                world.gateway(left).get_mpc_sender::<M>(
                    &ChannelId::new(right, Gate::default()),
                    TotalRecords::specified(total_records).unwrap(),
                    active_work.try_into().unwrap(),
                ),
                world
                    .gateway(right)
                    .get_mpc_receiver::<M>(&ChannelId::new(left, Gate::default())),
            )
        }

        async fn circuit<M>(
            send_channel: SendingEnd<Role, M>,
            recv_channel: MpcReceivingEnd<M>,
            active_work: usize,
            total_records: usize,
            msg: M,
        ) where
            M: MpcMessage + Clone + PartialEq,
        {
            let last_batch_size = total_records % active_work;
            let last_batch = total_records / active_work;

            let barrier = Arc::new(Barrier::new(active_work));
            let last_batch_barrier = Arc::new(Barrier::new(last_batch_size));

            // perform "multiplication-like" operation (send + subsequent receive)
            // and "validate": block the future until we have at least `active_work`
            // futures pending and unblock them all at the same time
            seq_join(
                active_work.try_into().unwrap(),
                stream::iter(std::iter::repeat(msg).take(total_records).enumerate()).map(
                    |(record_id, msg)| {
                        let send_channel = &send_channel;
                        let recv_channel = &recv_channel;
                        let barrier = Arc::clone(&barrier);
                        let last_batch_barrier = Arc::clone(&last_batch_barrier);
                        async move {
                            send_channel
                                .send(record_id.into(), msg.clone())
                                .await
                                .unwrap();
                            let r = recv_channel.receive(record_id.into()).await.unwrap();
                            // this simulates validate_record API by forcing futures to wait
                            // until the entire batch is validated by the last future in that batch
                            if record_id >= last_batch * active_work {
                                last_batch_barrier.wait().await;
                            } else {
                                barrier.wait().await;
                            }

                            assert_eq!(msg, r);
                        }
                    },
                ),
            )
            .collect::<Vec<_>>()
            .await;
        }

        let config = TestWorldConfig {
            gateway_config: GatewayConfig {
                active: active_work.try_into().unwrap(),
                read_size: read_size.try_into().unwrap(),
                ..Default::default()
            },
            ..Default::default()
        };

        let world = TestWorld::new_with(&config);
        let (h1_send_channel, h1_recv_channel) =
            duplex_channel(&world, Role::H1, Role::H2, total_records, active_work);
        let (h2_send_channel, h2_recv_channel) =
            duplex_channel(&world, Role::H2, Role::H1, total_records, active_work);

        join(
            circuit(
                h1_send_channel,
                h1_recv_channel,
                active_work,
                total_records,
                sample.clone(),
            ),
            circuit(
                h2_send_channel,
                h2_recv_channel,
                active_work,
                total_records,
                sample,
            ),
        )
        .await;
    }
}
