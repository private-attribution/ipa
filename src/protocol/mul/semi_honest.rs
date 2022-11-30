use crate::error::Error;
use crate::ff::Field;
use crate::helpers::{Direction, Role};
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{context::Context, RecordId};
use crate::secret_sharing::Replicated;

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018

/// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
/// their part, eventually producing 2/3 shares of the product and that is what this function
/// returns.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn secure_mul<F>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error>
where
    F: Field,
{
    let channel = ctx.mesh();

    // generate shared randomness.
    let prss = ctx.prss();
    let (s0, s1) = prss.generate_fields(record_id);
    let role = ctx.role();

    // compute the value (d_i) we want to send to the right helper (i+1)
    let right_d = a.left() * b.right() + a.right() * b.left() - s0;

    // notify helper on the right that we've computed our value
    channel
        .send(role.peer(Direction::Right), record_id, right_d)
        .await?;

    // Sleep until helper on the left sends us their (d_i-1) value
    let left_d = channel
        .receive(role.peer(Direction::Left), record_id)
        .await?;

    // now we are ready to construct the result - 2/3 secret shares of a * b.
    let lhs = a.left() * b.left() + left_d + s0;
    let rhs = a.right() * b.right() + right_d + s1;

    Ok(Replicated::new(lhs, rhs))
}

/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn multiply_two_shares_mostly_zeroes<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    match ctx.role() {
        Role::H1 => {
            let prss = &ctx.prss();
            let (s_3_1, _) = prss.generate_fields(record_id);

            // d_1 = a_1 * b_2 + a_2 * b_1 - s_3,1
            // d_1 = a_1 * b_2 + 0 * 0 - s_3,1
            let (a_1, a_2) = a.as_tuple();
            let (b_1, b_2) = b.as_tuple();
            debug_assert!(a_2 == F::ZERO);
            debug_assert!(b_1 == F::ZERO);

            let d_1 = a_1 * b_2 - s_3_1;

            // notify helper on the right that we've computed our value
            let channel = ctx.mesh();
            channel
                .send(ctx.role().peer(Direction::Right), record_id, d_1)
                .await?;

            Ok(Replicated::new(s_3_1, d_1))
        }
        Role::H2 => {
            // d_2 = a_2 * b_3 + a_3 * b_2 - s_1,2
            // d_2 = 0 * 0 + 0 * b - s_1,2
            // d_2 = s_1,2
            // d_2 is a constant, known in advance. So we can replace it with zero
            // And there is no need to send it.

            // Sleep until helper on the left sends us their (d_i-1) value
            let channel = ctx.mesh();
            let d_1 = channel
                .receive(ctx.role().peer(Direction::Left), record_id)
                .await?;

            Ok(Replicated::new(d_1, F::ZERO))
        }
        Role::H3 => {
            // d_3 = a_3 * b_1 + a_1 * b_3 - s_2,3
            // d_3 = 0 * 0 + a * 0 - s_2,3
            // d_3 = s_2,3
            // d_3 is a constant, known in advance. So we can replace it with zero
            // And there is no need to send it.

            let prss = &ctx.prss();
            let (_, s_3_1) = prss.generate_fields(record_id);

            Ok(Replicated::new(F::ZERO, s_3_1))
        }
    }
}

/// Another highly specialized variant of the IKHC multiplication protocol which is only valid
/// in the case where one of the two secret sharings has 2 of the 3 shares set to zero.
///
/// Original IKHC multiplication protocol from:
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
///
/// Optimizations taken from Appendix F: "Conversion Protocols" from the paper:
/// "Adam in Private: Secure and Fast Training of Deep Neural Networks with Adaptive Moment Estimation"
/// by Nuttapong Attrapadung, Koki Hamada, Dai Ikarashi, Ryo Kikuchi*, Takahiro Matsuda,
/// Ibuki Mishina, Hiraku Morita, and Jacob C. N. Schuldt
///
/// This protocol can only be used in the case where:
/// Helper 1 has shares `(a_1, a_2)` and `(0, 0)`
/// Helper 2 has shares `(a_2, a_3)` and `(0, b)`
/// Helper 3 has shares `(a_3, a_1)` and `(b, 0)`
///
/// In the IKHC multiplication protocol, each helper computes `d_i` as
/// `d_i = a_i * b_i+1 + a_i+1 * b_i - s_i+2,i`
/// and sends it to the next helper.
/// But in this case, `d_1` is publicly known to all the helper parties
/// and can be replaced with a constant, e.g. 0. Therefore, it does not need to be sent.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn multiply_one_share_mostly_zeroes<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    let prss = &ctx.prss();
    let (s_left, s_right) = prss.generate_fields(record_id);

    match ctx.role() {
        Role::H1 => {
            // d_1 = a_1 * b_2 + a_2 * b_1 - s_3,1
            // d_1 = a_1 * 0 + a_2 * 0 - s_3,1
            // d_1 = - s_3,1
            // d_2 is a constant, known in advance. So we can replace it with zero
            // And there is no need to send it.

            // Sleep until helper on the left sends us their (d_i-1) value
            let channel = ctx.mesh();
            let d_3 = channel
                .receive(ctx.role().peer(Direction::Left), record_id)
                .await?;

            Ok(Replicated::new(d_3, s_right))
        }
        Role::H2 => {
            // d_2 = a_2 * b_3 + a_3 * b_2 - s_1,2
            // d_2 = a_2 * b_3 + a_3 * 0 - s_1,2
            // d_2 = a_2 * b_3 - s_1,2
            let (a_2, a_3) = a.as_tuple();
            let (b_2, b_3) = b.as_tuple();
            debug_assert!(b_2 == F::ZERO);

            let d_2 = a_2 * b_3 - s_left;

            // notify helper on the right that we've computed our value
            let channel = ctx.mesh();
            channel
                .send(ctx.role().peer(Direction::Right), record_id, d_2)
                .await?;

            Ok(Replicated::new(s_left, a_3 * b_3 + d_2 + s_right))
        }
        Role::H3 => {
            // d_3 = a_3 * b_1 + a_1 * b_3 - s_2,3
            // d_3 = a_3 * 0 + a_1 * b_3 - s_2,3
            // d_3 = a_1 * b_3 - s_2,3
            let (a_3, a_1) = a.as_tuple();
            let (b_3, b_1) = b.as_tuple();
            debug_assert!(b_1 == F::ZERO);

            let d_3 = a_1 * b_3 - s_left;

            // notify helper on the right that we've computed our value
            let channel = ctx.mesh();
            channel
                .send(ctx.role().peer(Direction::Right), record_id, d_3)
                .await?;

            // Sleep until helper on the left sends us their (d_i-1) value
            let d_2 = channel
                .receive(ctx.role().peer(Direction::Left), record_id)
                .await?;

            Ok(Replicated::new(a_3 * b_3 + d_2 + s_left, d_3))
        }
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod regular_mul_tests {
    use crate::ff::{Field, Fp31};
    use crate::protocol::mul::SecureMul;
    use crate::protocol::{QueryId, RecordId};
    use crate::rand::{thread_rng, Rng};
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use futures::future::try_join_all;
    use rand::distributions::Standard;
    use rand::prelude::Distribution;
    use std::iter::{repeat, zip};

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::new(QueryId);

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
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let res = world
            .semi_honest((a, b), |ctx, (a, b)| async move {
                ctx.multiply(RecordId::from(0), &a, &b).await.unwrap()
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
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a: Vec<_> = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect();
        let b: Vec<_> = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a * b).collect();
        let results = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                try_join_all(zip(repeat(ctx), zip(a_shares, b_shares)).enumerate().map(
                    |(i, (ctx, (a_share, b_share)))| async move {
                        ctx.multiply(RecordId::from(i), &a_share, &b_share).await
                    },
                ))
                .await
                .unwrap()
            })
            .await;
        assert_eq!(expected, results.reconstruct());
    }

    async fn multiply_sync<F>(world: &TestWorld<F>, a: u128, b: u128) -> u128
    where
        F: Field,
        (F, F): Sized,
        Standard: Distribution<F>,
    {
        let a = F::from(a);
        let b = F::from(b);

        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                ctx.multiply(RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct().as_u128()
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod specialized_mul_tests {
    use std::iter::{repeat, zip};

    use super::{multiply_one_share_mostly_zeroes, multiply_two_shares_mostly_zeroes};
    use crate::ff::Fp31;
    use crate::protocol::mul::test::{SpecializedA, SpecializedB, SpecializedC};
    use crate::protocol::{QueryId, RecordId};
    use crate::rand::{thread_rng, Rng};
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use futures::future::try_join_all;

    #[tokio::test]
    async fn specialized_1() {
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let input = (SpecializedA(a), SpecializedB(b));
        let result = world
            .semi_honest(input, |ctx, (a_share, b_share)| async move {
                multiply_two_shares_mostly_zeroes(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(a * b, result.reconstruct());
    }

    #[tokio::test]
    async fn specialized_1_parallel() {
        const COUNT: usize = 10;
        let world = TestWorld::new(QueryId);

        let mut rng = rand::thread_rng();
        let a: Vec<_> = (0..COUNT)
            .map(|_| SpecializedA(rng.gen::<Fp31>()))
            .collect();
        let b: Vec<_> = (0..COUNT)
            .map(|_| SpecializedB(rng.gen::<Fp31>()))
            .collect();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a.0 * b.0).collect();
        let result = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                try_join_all(zip(repeat(ctx), zip(a_shares, b_shares)).enumerate().map(
                    |(i, (ctx, (a_share, b_share)))| async move {
                        multiply_two_shares_mostly_zeroes(
                            ctx,
                            RecordId::from(i),
                            &a_share,
                            &b_share,
                        )
                        .await
                    },
                ))
                .await
                .unwrap()
            })
            .await;
        assert_eq!(expected, result.reconstruct());
    }

    #[tokio::test]
    async fn specialized_2() {
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let input = (a, SpecializedC(b));
        let result = world
            .semi_honest(input, |ctx, (a_share, b_share)| async move {
                multiply_one_share_mostly_zeroes(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;
        assert_eq!(a * b, result.reconstruct());
    }

    #[tokio::test]
    async fn specialized_2_parallel() {
        const COUNT: usize = 10;
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a: Vec<_> = (0..COUNT).map(|_| rng.gen::<Fp31>()).collect();
        let b: Vec<_> = (0..COUNT)
            .map(|_| SpecializedC(rng.gen::<Fp31>()))
            .collect();
        let expected: Vec<_> = zip(a.iter(), b.iter()).map(|(&a, &b)| a * b.0).collect();
        let result = world
            .semi_honest((a, b), |ctx, (a_shares, b_shares)| async move {
                try_join_all(zip(repeat(ctx), zip(a_shares, b_shares)).enumerate().map(
                    |(i, (ctx, (a_share, b_share)))| async move {
                        multiply_one_share_mostly_zeroes(ctx, RecordId::from(i), &a_share, &b_share)
                            .await
                    },
                ))
                .await
                .unwrap()
            })
            .await;
        assert_eq!(expected, result.reconstruct());
    }
}
