#[cfg(all(feature = "shuttle", test))]
mod randomized {
    use crate::ff::Fp32BitPrime;
    use crate::helpers::Direction;
    use crate::protocol::context::{Context, SemiHonestContext};
    use crate::protocol::{QueryId, RecordId};
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::Reconstruct;
    use crate::test_fixture::{Runner, TestWorld};
    use futures_util::future::{try_join, try_join_all};

    #[test]
    fn send_receive_sequential() {
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let world = TestWorld::new(QueryId);
                    let input = (0u32..100).map(Fp32BitPrime::from).collect::<Vec<_>>();

                    let output = world
                        .semi_honest(
                            input.clone(),
                            |ctx: SemiHonestContext<'_, Fp32BitPrime>, mut shares| async move {
                                let (left_ctx, right_ctx) =
                                    (ctx.narrow("left"), ctx.narrow("right"));
                                let left_channel = left_ctx.mesh();
                                let right_channel = right_ctx.mesh();
                                let left_peer = ctx.role().peer(Direction::Left);
                                let right_peer = ctx.role().peer(Direction::Right);

                                // send all shares to the right peer
                                for (i, share) in shares.iter().enumerate() {
                                    let record_id = RecordId::from(i);
                                    left_channel
                                        .send(right_peer, record_id, share.left())
                                        .await
                                        .unwrap();
                                    right_channel
                                        .send(right_peer, record_id, share.right())
                                        .await
                                        .unwrap();
                                }

                                // receive all shares from the left peer
                                for (i, share) in shares.iter_mut().enumerate() {
                                    let record_id = RecordId::from(i);
                                    let left: Fp32BitPrime =
                                        left_channel.receive(left_peer, record_id).await.unwrap();
                                    let right: Fp32BitPrime =
                                        right_channel.receive(left_peer, record_id).await.unwrap();

                                    *share = Replicated::new(left, right);
                                }

                                // each helper just swapped their shares, i.e. H1 now holds
                                // H3 shares, H2 holds H1 shares, etc.
                                shares
                            },
                        )
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
        shuttle::check_random(
            || {
                shuttle::future::block_on(async {
                    let world = TestWorld::new(QueryId);
                    let input = (0u32..10).map(Fp32BitPrime::from).collect::<Vec<_>>();

                    let output = world
                        .semi_honest(
                            input.clone(),
                            |ctx: SemiHonestContext<'_, Fp32BitPrime>, shares| async move {
                                let (left_ctx, right_ctx) =
                                    (ctx.narrow("left"), ctx.narrow("right"));
                                let left_channel = left_ctx.mesh();
                                let right_channel = right_ctx.mesh();
                                let left_peer = ctx.role().peer(Direction::Left);
                                let right_peer = ctx.role().peer(Direction::Right);

                                // send all shares to the right peer in parallel
                                let mut futures = Vec::with_capacity(shares.len());
                                for (i, share) in shares.iter().enumerate() {
                                    let record_id = RecordId::from(i);
                                    futures.push(left_channel.send(
                                        right_peer,
                                        record_id,
                                        share.left(),
                                    ));
                                    futures.push(right_channel.send(
                                        right_peer,
                                        record_id,
                                        share.left(),
                                    ));
                                }
                                try_join_all(futures)
                                    .await
                                    .unwrap()
                                    .into_iter()
                                    .for_each(drop);

                                // receive all shares from the left peer in parallel
                                let mut futures = Vec::with_capacity(shares.len());
                                for i in 0..shares.len() {
                                    let record_id = RecordId::from(i);
                                    futures.push(try_join(
                                        left_channel.receive::<Fp32BitPrime>(left_peer, record_id),
                                        right_channel.receive::<Fp32BitPrime>(left_peer, record_id),
                                    ));
                                }

                                let result = try_join_all(futures).await.unwrap();

                                result.into_iter().map(Replicated::from).collect::<Vec<_>>()
                            },
                        )
                        .await
                        .reconstruct();

                    assert_eq!(input, output);
                });
            },
            1000,
        );
    }
}
