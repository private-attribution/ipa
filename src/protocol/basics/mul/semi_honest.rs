use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        basics::{mul::sparse::MultiplyWork, MultiplyZeroPositions},
        context::{Context, SemiHonestContext},
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::replicated::{
        semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
    },
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
pub async fn multiply<F>(
    ctx: SemiHonestContext<'_>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
    zeros: MultiplyZeroPositions,
) -> Result<Replicated<F>, Error>
where
    F: Field,
{
    let role = ctx.role();
    let [need_to_recv, need_to_send, need_random_right] = zeros.work_for(role);
    zeros.0.check(role, "a", a);
    zeros.1.check(role, "b", b);

    // Shared randomness used to mask the values that are sent.
    let (s0, s1) = ctx.prss().generate_fields(record_id);

    let mut rhs = a.right() * b.right();
    if need_to_send {
        // Compute the value (d_i) we want to send to the right helper (i+1).
        let right_d = a.left() * b.right() + a.right() * b.left() - s0;

        ctx.send_channel(role.peer(Direction::Right))
            .send(record_id, right_d)
            .await?;
        rhs += right_d;
    } else {
        debug_assert_eq!(a.left() * b.right() + a.right() * b.left(), F::ZERO);
    }
    // Add randomness to this value whether we sent or not, depending on whether the
    // peer to the right needed to send.  If they send, they subtract randomness,
    // and we need to add to our share to compensate.
    if need_random_right {
        rhs += s1;
    }

    // Sleep until helper on the left sends us their (d_i-1) value.
    let mut lhs = a.left() * b.left();
    if need_to_recv {
        let left_d = ctx
            .recv_channel(role.peer(Direction::Left))
            .receive(record_id)
            .await?;
        lhs += left_d;
    }
    // If we send, we subtract randomness, so we need to add to our share.
    if need_to_send {
        lhs += s0;
    }

    Ok(Replicated::new(lhs, rhs))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use crate::{
        ff::{Field, Fp31},
        protocol::{basics::SecureMul, context::Context, RecordId},
        rand::{thread_rng, Rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::distributions::{Distribution, Standard};
    use std::iter::{repeat, zip};

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::default();

        assert_eq!(30, multiply_sync::<Fp31>(&world, 6, 5).await);
        assert_eq!(25, multiply_sync::<Fp31>(&world, 5, 5).await);
        // assert_eq!(7, multiply_sync::<Fp31>(&world, 7, 1).await);
        // assert_eq!(0, multiply_sync::<Fp31>(&world, 0, 14).await);
        // assert_eq!(8, multiply_sync::<Fp31>(&world, 7, 10).await);
        // assert_eq!(4, multiply_sync::<Fp31>(&world, 5, 7).await);
        // assert_eq!(1, multiply_sync::<Fp31>(&world, 16, 2).await);
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
        let a: Vec<_> = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect();
        let b: Vec<_> = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a * b).collect();
        let results = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                try_join_all(
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
            })
            .await;
        assert_eq!(expected, results.reconstruct());
    }

    async fn multiply_sync<F>(world: &TestWorld, a: u128, b: u128) -> u128
    where
        F: Field,
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let a = F::from(a);
        let b = F::from(b);

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
}
