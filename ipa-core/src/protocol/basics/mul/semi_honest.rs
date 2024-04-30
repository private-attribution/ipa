use async_trait::async_trait;

use crate::{
    error::Error,
    ff::{Field, PrimeField},
    helpers::Direction,
    protocol::{
        basics::{mul::sparse::MultiplyWork, MultiplyZeroPositions},
        context::{
            dzkp_semi_honest::DZKPUpgraded as SemiHonestDZKPUpgraded,
            semi_honest::{Context as SemiHonestContext, Upgraded as UpgradedSemiHonestContext},
            Context,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{
        replicated::semi_honest::AdditiveShare as Replicated, FieldSimd, SharedValueArray,
        Vectorizable,
    },
    sharding,
};

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
/// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
/// their part, eventually producing 2/3 shares of the product and that is what this function
/// returns.
///
///
/// The `zeros_at` argument indicates where there are known zeros in the inputs.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn multiply<C, F, const N: usize>(
    ctx: C,
    record_id: RecordId,
    a: &Replicated<F, N>,
    b: &Replicated<F, N>,
    zeros: MultiplyZeroPositions,
) -> Result<Replicated<F, N>, Error>
where
    C: Context,
    F: Field + FieldSimd<N>,
{
    let role = ctx.role();
    let [need_to_recv, need_to_send, need_random_right] = zeros.work_for(role);
    zeros.0.check(role, "a", a);
    zeros.1.check(role, "b", b);

    // Shared randomness used to mask the values that are sent.
    let (s0, s1) = ctx
        .prss()
        .generate::<(<F as Vectorizable<N>>::Array, _), _>(record_id);

    let mut rhs = a.right_arr().clone() * b.right_arr();

    if need_to_send {
        // Compute the value (d_i) we want to send to the right helper (i+1).
        let right_d =
            a.left_arr().clone() * b.right_arr() + a.right_arr().clone() * b.left_arr() - &s0;

        ctx.send_channel::<<F as Vectorizable<N>>::Array>(role.peer(Direction::Right))
            .send(record_id, &right_d)
            .await?;
        rhs += right_d;
    } else {
        debug_assert_eq!(
            a.left_arr().clone() * b.right_arr() + a.right_arr().clone() * b.left_arr(),
            <<F as Vectorizable<N>>::Array as SharedValueArray<F>>::ZERO_ARRAY
        );
    }
    // Add randomness to this value whether we sent or not, depending on whether the
    // peer to the right needed to send.  If they send, they subtract randomness,
    // and we need to add to our share to compensate.
    if need_random_right {
        rhs += s1;
    }

    // Sleep until helper on the left sends us their (d_i-1) value.
    let mut lhs = a.left_arr().clone() * b.left_arr();
    if need_to_recv {
        let left_d: <F as Vectorizable<N>>::Array = ctx
            .recv_channel(role.peer(Direction::Left))
            .receive(record_id)
            .await?;
        lhs += left_d;
    }
    // If we send, we subtract randomness, so we need to add to our share.
    if need_to_send {
        lhs += s0;
    }

    Ok(Replicated::new_arr(lhs, rhs))
}

/// Implement secure multiplication for semi-honest contexts with replicated secret sharing.
//
// TODO: This impl should be removed, and the (relatively few) things that truly need
// to invoke multiplies on a base context should call the routines directly. However,
// there are too many places that unnecessarily invoke multiplies on a base context
// to make that change right now.
#[async_trait]
impl<'a, B, F, const N: usize> super::SecureMul<SemiHonestContext<'a, B>> for Replicated<F, N>
where
    B: sharding::ShardBinding,
    F: Field + FieldSimd<N>,
{
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: SemiHonestContext<'a, B>,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        SemiHonestContext<'a, B>: 'fut,
    {
        multiply(ctx, record_id, self, rhs, zeros_at).await
    }
}

/// Implement secure multiplication for semi-honest upgraded
#[async_trait]
impl<'a, B, F, const N: usize> super::SecureMul<UpgradedSemiHonestContext<'a, B, F>>
    for Replicated<F, N>
where
    B: sharding::ShardBinding,
    F: PrimeField + FieldSimd<N>,
{
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: UpgradedSemiHonestContext<'a, B, F>,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        UpgradedSemiHonestContext<'a, B, F>: 'fut,
    {
        multiply(ctx, record_id, self, rhs, zeros_at).await
    }
}

/// Implement secure multiplication for semi-honest dzkpupgraded
#[async_trait]
impl<'a, B, F, const N: usize> super::SecureMul<SemiHonestDZKPUpgraded<'a, B>> for Replicated<F, N>
where
    B: sharding::ShardBinding,
    F: Field + FieldSimd<N>,
{
    async fn multiply_sparse<'fut>(
        &self,
        rhs: &Self,
        ctx: SemiHonestDZKPUpgraded<'a, B>,
        record_id: RecordId,
        zeros_at: MultiplyZeroPositions,
    ) -> Result<Self, Error>
    where
        SemiHonestDZKPUpgraded<'a, B>: 'fut,
    {
        multiply(ctx, record_id, self, rhs, zeros_at).await
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use std::{
        array,
        iter::{repeat, zip},
        time::Instant,
    };

    use rand::distributions::{Distribution, Standard};

    use super::multiply;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime, U128Conversions},
        helpers::TotalRecords,
        protocol::{
            basics::{SecureMul, ZeroPositions},
            context::Context,
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::replicated::semi_honest::AdditiveShare,
        seq_join::SeqJoin,
        test_fixture::{Reconstruct, ReconstructArr, Runner, TestWorld},
    };

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::default();

        assert_eq!(30, multiply_sync::<Fp31>(&world, 6, 5).await);
        assert_eq!(25, multiply_sync::<Fp31>(&world, 5, 5).await);
        assert_eq!(7, multiply_sync::<Fp31>(&world, 7, 1).await);
        assert_eq!(0, multiply_sync::<Fp31>(&world, 0, 14).await);
        assert_eq!(8, multiply_sync::<Fp31>(&world, 7, 10).await);
        assert_eq!(4, multiply_sync::<Fp31>(&world, 5, 7).await);
        assert_eq!(1, multiply_sync::<Fp31>(&world, 16, 2).await);
    }

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let res = world
            .semi_honest((a, b), |ctx, (a, b)| async move {
                a.multiply(&b, ctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }

    /// This test ensures that many secure multiplications can run concurrently as long as
    /// they all have unique id associated with it. Basically it validates
    /// `TestHelper`'s ability to distinguish messages of the same type sent towards helpers
    /// executing multiple same type protocols
    #[tokio::test]
    pub async fn concurrent_mul() {
        const COUNT: usize = 10;
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>();
        let b = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect::<Vec<_>>();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a * b).collect();
        let results = world
            .semi_honest(
                (a.into_iter(), b.into_iter()),
                |ctx, (a_shares, b_shares)| async move {
                    ctx.try_join(
                        zip(
                            repeat(ctx.set_total_records(COUNT)),
                            zip(a_shares, b_shares),
                        )
                        .enumerate()
                        .map(|(i, (ctx, (a_share, b_share)))| async move {
                            a_share.multiply(&b_share, ctx, RecordId::from(i)).await
                        }),
                    )
                    .await
                    .unwrap()
                },
            )
            .await;
        assert_eq!(expected, results.reconstruct());
    }

    async fn multiply_sync<F>(world: &TestWorld, a: u128, b: u128) -> u128
    where
        F: Field + U128Conversions,
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let a = F::try_from(a).unwrap();
        let b = F::try_from(b).unwrap();

        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                a_share
                    .multiply(&b_share, ctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct().as_u128()
    }

    #[tokio::test]
    pub async fn wide_mul() {
        const COUNT: usize = 32;
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a: [Fp32BitPrime; COUNT] = (0..COUNT)
            .map(|_| rng.gen::<Fp32BitPrime>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let b: [Fp32BitPrime; COUNT] = (0..COUNT)
            .map(|_| rng.gen::<Fp32BitPrime>())
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let expected: [Fp32BitPrime; COUNT] = zip(a.iter(), b.iter())
            .map(|(&a, &b)| a * b)
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        let results = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                multiply(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_shares,
                    &b_shares,
                    ZeroPositions::NONE,
                )
                .await
                .unwrap()
            })
            .await;
        assert_eq!(expected, results.reconstruct_arr());
    }

    // The manymult test is a microbenchmark. The test generates a DxW matrix of field elements. The
    // matrix is reduced to a single W-element row vector by taking the element-wise product of the
    // D values in each column. The non-vectorized implementation (manymult_novec) simply does a
    // parallel_join of W semi-honest multiplies. The vectorized implementation (manymult_vec)
    // processes a row at a time. For manymult_vec, MANYMULT_WIDTH must match a supported
    // vectorization width.
    const MANYMULT_ITERS: usize = 512;
    const MANYMULT_WIDTH: usize = 32;

    #[tokio::test]
    pub async fn manymult_novec() {
        let world = TestWorld::default();
        let mut rng = thread_rng();
        let mut inputs = Vec::<Vec<Fp32BitPrime>>::new();
        for _ in 0..MANYMULT_ITERS {
            inputs.push(
                (0..MANYMULT_WIDTH)
                    .map(|_| Fp32BitPrime::try_from(u128::from(rng.gen_range(0u32..100))).unwrap())
                    .collect::<Vec<_>>(),
            );
        }
        let expected = inputs
            .iter()
            .fold(None, |acc: Option<Vec<Fp32BitPrime>>, b| match acc {
                Some(a) => Some(a.iter().zip(b.iter()).map(|(&a, &b)| a * b).collect()),
                None => Some(b.clone()),
            })
            .unwrap();

        let begin = Instant::now();
        let result = world
            .semi_honest(
                inputs.into_iter().map(IntoIterator::into_iter),
                |ctx, share: Vec<Vec<AdditiveShare<Fp32BitPrime>>>| async move {
                    let ctx = ctx.set_total_records(MANYMULT_ITERS * MANYMULT_WIDTH);
                    let mut iter = share.iter();
                    let mut val = iter.next().unwrap().clone();
                    for i in 1..MANYMULT_ITERS {
                        let cur = iter.next().unwrap();
                        let mut res = Vec::with_capacity(MANYMULT_WIDTH);
                        for j in 0..MANYMULT_WIDTH {
                            res.push(val[j].multiply(
                                &cur[j],
                                ctx.clone(),
                                RecordId::from(MANYMULT_WIDTH * (i - 1) + j),
                            ));
                        }
                        val = ctx.parallel_join(res).await.unwrap();
                    }
                    val
                },
            )
            .await;
        tracing::debug!("Protocol execution time: {:?}", begin.elapsed());
        assert_eq!(expected, result.reconstruct());
    }

    #[tokio::test]
    pub async fn manymult_vec() {
        let world = TestWorld::default();
        let mut rng = thread_rng();
        let mut inputs = Vec::<[Fp32BitPrime; MANYMULT_WIDTH]>::new();
        for _ in 0..MANYMULT_ITERS {
            inputs.push(array::from_fn(|_| rng.gen()));
        }
        let expected = inputs
            .iter()
            .fold(None, |acc: Option<Vec<Fp32BitPrime>>, b| match acc {
                Some(a) => Some(a.iter().zip(b.iter()).map(|(&a, &b)| a * b).collect()),
                None => Some(b.to_vec()),
            })
            .unwrap();

        let begin = Instant::now();
        let result = world
            .semi_honest(
                inputs.into_iter(),
                |ctx, share: Vec<AdditiveShare<Fp32BitPrime, MANYMULT_WIDTH>>| async move {
                    // The output of each row is input to the next row, so no parallelization
                    // across rows is possible. Thus we set TotalRecords::Indeterminate, which
                    // flushes after every record. If a row were larger than one record, we could
                    // instead configure the active work in TestWorld to match the row size.
                    let ctx = ctx.set_total_records(TotalRecords::Indeterminate);
                    let mut iter = share.iter();
                    let mut val = iter.next().unwrap().clone();
                    for i in 1..MANYMULT_ITERS {
                        val = multiply(
                            ctx.clone(),
                            RecordId::from(i - 1),
                            &val,
                            iter.next().unwrap(),
                            ZeroPositions::NONE,
                        )
                        .await
                        .unwrap();
                    }
                    val
                },
            )
            .await;
        tracing::debug!("Protocol execution time: {:?}", begin.elapsed());
        assert_eq!(expected, result.reconstruct_arr());
    }
}
