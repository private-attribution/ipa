#![cfg(all(feature = "shuttle", test))]

use crate::{
    ff::{Field, Fp32BitPrime},
    helpers::{Direction, GatewayConfig},
    protocol::{context::Context, RecordId},
    secret_sharing::replicated::{
        semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
    },
    seq_join::seq_try_join_all,
    test_fixture::{Reconstruct, Runner, TestWorld, TestWorldConfig},
};
use futures::future::try_join;

#[test]
fn send_receive_sequential() {
    type TestField = Fp32BitPrime;
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                let input = (0u32..11).map(TestField::truncate_from).collect::<Vec<_>>();
                let config = TestWorldConfig {
                    gateway_config: GatewayConfig::symmetric_buffers::<TestField>(input.len()),
                    ..Default::default()
                };
                let world = TestWorld::new_with(config);

                let output = world
                    .semi_honest(input.clone(), |ctx, mut shares| async move {
                        let ctx = ctx.set_total_records(shares.len());
                        let (left_ctx, right_ctx) = (ctx.narrow("left"), ctx.narrow("right"));
                        let right_peer = ctx.role().peer(Direction::Right);
                        let left_channel = left_ctx.send_channel(right_peer);
                        let right_channel = right_ctx.send_channel(right_peer);

                        // send all shares to the right peer
                        for (i, share) in shares.iter().enumerate() {
                            let record_id = RecordId::from(i);
                            left_channel.send(record_id, share.left()).await.unwrap();
                            right_channel.send(record_id, share.right()).await.unwrap();
                        }

                        let left_peer = ctx.role().peer(Direction::Left);
                        let left_channel = left_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                        let right_channel = right_ctx.recv_channel::<Fp32BitPrime>(left_peer);

                        // receive all shares from the left peer
                        for (i, share) in shares.iter_mut().enumerate() {
                            let record_id = RecordId::from(i);
                            let left = left_channel.receive(record_id).await.unwrap();
                            let right = right_channel.receive(record_id).await.unwrap();

                            *share = Replicated::new(left, right);
                        }

                        // each helper just swapped their shares, i.e. H1 now holds
                        // H3 shares, H2 holds H1 shares, etc.
                        shares
                    })
                    .await
                    .reconstruct();

                assert_eq!(input, output);
            });
        },
        1000,
    );
}

#[test]
fn send_receive_parallel() {
    type TestField = Fp32BitPrime;
    shuttle::check_random(
        || {
            shuttle::future::block_on(async {
                let input = (0u32..11).map(TestField::truncate_from).collect::<Vec<_>>();
                let config = TestWorldConfig {
                    gateway_config: GatewayConfig::symmetric_buffers::<TestField>(input.len()),
                    ..Default::default()
                };
                let world = TestWorld::new_with(config);

                let output = world
                    .semi_honest(input.clone(), |ctx, shares| async move {
                        let ctx = ctx.set_total_records(shares.len());
                        let (left_ctx, right_ctx) = (ctx.narrow("left"), ctx.narrow("right"));
                        let left_peer = ctx.role().peer(Direction::Left);
                        let right_peer = ctx.role().peer(Direction::Right);

                        // send all shares to the right peer in parallel
                        let left_channel = left_ctx.send_channel(right_peer);
                        let right_channel = right_ctx.send_channel(right_peer);

                        let mut futures = Vec::with_capacity(shares.len());
                        for (i, share) in shares.iter().enumerate() {
                            let record_id = RecordId::from(i);
                            futures.push(left_channel.send(record_id, share.left()));
                            futures.push(right_channel.send(record_id, share.right()));
                        }
                        seq_try_join_all(futures)
                            .await
                            .unwrap()
                            .into_iter()
                            .for_each(drop);

                        // receive all shares from the left peer in parallel
                        let left_channel = left_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                        let right_channel = right_ctx.recv_channel::<Fp32BitPrime>(left_peer);
                        let mut futures = Vec::with_capacity(shares.len());
                        for i in 0..shares.len() {
                            let record_id = RecordId::from(i);
                            futures.push(try_join(
                                left_channel.receive(record_id),
                                right_channel.receive(record_id),
                            ));
                        }

                        let result = seq_try_join_all(futures).await.unwrap();

                        result.into_iter().map(Replicated::from).collect::<Vec<_>>()
                    })
                    .await
                    .reconstruct();

                assert_eq!(input, output);
            });
        },
        1000,
    );
}
