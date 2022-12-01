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
///
/// The `who_sends` argument indicates who is sending (self, left, right),
/// which we interpret as (we send, we receive, we add randomness to our right).
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn multiply<F>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
    who_sends: (bool, bool, bool),
) -> Result<Replicated<F>, Error>
where
    F: Field,
{
    let role = ctx.role();
    let (need_to_send, need_to_recv, need_random_right) = who_sends;

    // generate shared randomness.
    let prss = ctx.prss();
    let (s0, s1) = prss.generate_fields(record_id);

    let channel = ctx.mesh();
    let rhs = if need_to_send {
        // compute the value (d_i) we want to send to the right helper (i+1)
        let right_d = a.left() * b.right() + a.right() * b.left() - s0;

        // notify helper on the right that we've computed our value
        channel
            .send(role.peer(Direction::Right), record_id, right_d)
            .await?;
        a.right() * b.right() + right_d
    } else {
        debug_assert_eq!(a.left() * b.right() + a.right() * b.left(), F::ZERO);
        F::ZERO
    };
    // Add randomness to this value whether we sent or not, depending on whether the
    // peer to the right needed to send.  If they send, they subtract randomness,
    // and we need to add to our share to compensate.
    let rhs = rhs + if need_random_right { s1 } else { F::ZERO };

    // Sleep until helper on the left sends us their (d_i-1) value
    let lhs = if need_to_recv {
        let left_d = channel
            .receive(role.peer(Direction::Left), record_id)
            .await?;
        a.left() * b.left() + left_d
    } else {
        F::ZERO
    };
    // If we send, we subtract randomness, so we need to add to our share.
    let lhs = lhs + if need_to_send { s0 } else { F::ZERO };

    Ok(Replicated::new(lhs, rhs))
}

/// Determine whether multiplication for helper X requires sending or receiving.
/// Argument is a description of which items are zero for shares at each helper.
/// This indicates whether the left share is zero at each.
/// Setting a = [true, false, true] means:
///    H1 has (0, ?), H2 has (?, 0), and H3 has (0, 0)
/// Return value is (self, left, right)
#[must_use]
pub fn sparse_mul_work(role: Role, a: [bool; 3], b: [bool; 3]) -> (bool, bool, bool) {
    let a_left_left = a[role.peer(Direction::Left) as usize];
    let b_left_left = b[role.peer(Direction::Left) as usize];
    let a_left = a[role as usize];
    let b_left = b[role as usize];
    let a_right = a[role.peer(Direction::Right) as usize];
    let b_right = b[role.peer(Direction::Right) as usize];
    let can_skip_send = (a_left || b_right) && (a_right || b_left);
    let can_skip_recv = (a_left_left || b_left) && (a_left || b_left_left);
    let can_skip_rand = (a_right || b_left_left) && (a_left_left || b_right);
    (!can_skip_send, !can_skip_recv, !can_skip_rand)
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

    use crate::ff::Fp31;
    use crate::helpers::Role;
    use crate::protocol::context::Context;
    use crate::protocol::mul::test::{SpecializedA, SpecializedB, SpecializedC};
    use crate::protocol::mul::{sparse_mul_work, SecureMul};
    use crate::protocol::{QueryId, RecordId};
    use crate::rand::{thread_rng, Rng};
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};
    use futures::future::try_join_all;

    #[test]
    fn work_profile() {
        for role in Role::all() {
            assert_eq!(
                (true, true, true),
                sparse_mul_work(*role, [false, false, false], [false, false, false])
            );
        }
        // Now do profile for b having two known zero values.
        assert_eq!(
            (false, true, true),
            sparse_mul_work(Role::H1, [false, false, false], [true, true, false])
        );
        assert_eq!(
            (true, false, true),
            sparse_mul_work(Role::H2, [false, false, false], [true, true, false])
        );
        assert_eq!(
            (true, true, false),
            sparse_mul_work(Role::H3, [false, false, false], [true, true, false])
        );
        assert_eq!(
            (true, false, true),
            sparse_mul_work(Role::H1, [false, false, false], [true, false, true])
        );
        assert_eq!(
            (true, true, false),
            sparse_mul_work(Role::H2, [false, false, false], [true, false, true])
        );
        assert_eq!(
            (false, true, true),
            sparse_mul_work(Role::H3, [false, false, false], [true, false, true])
        );
    }

    #[tokio::test]
    async fn specialized_1() {
        let world = TestWorld::new(QueryId);

        let mut rng = thread_rng();
        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();
        let input = (SpecializedA(a), SpecializedB(b));
        let result = world
            .semi_honest(input, |ctx, (a_share, b_share)| async move {
                let work = sparse_mul_work(ctx.role(), [false, true, true], [true, false, true]);
                ctx.multiply_sparse(RecordId::from(0), &a_share, &b_share, work)
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
                        let work =
                            sparse_mul_work(ctx.role(), [false, true, true], [true, false, true]);
                        ctx.multiply_sparse(RecordId::from(i), &a_share, &b_share, work)
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
                let work = sparse_mul_work(ctx.role(), [false, false, false], [true, true, false]);
                ctx.multiply_sparse(RecordId::from(0), &a_share, &b_share, work)
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
                        let work =
                            sparse_mul_work(ctx.role(), [false, false, false], [true, true, false]);
                        ctx.multiply_sparse(RecordId::from(i), &a_share, &b_share, work)
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
