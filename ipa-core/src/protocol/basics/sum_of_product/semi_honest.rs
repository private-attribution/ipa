use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{context::Context, prss::SharedRandomness, RecordId},
    secret_sharing::replicated::{
        semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
    },
};

/// Sum of product protocol developed using IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// Given two vectors x and y `[x1, x2, .., xn]` and `[y1, y2, .., yn]`, it returns `[x1 · y1 + x2 · y2 + ... + xn · yn]`
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
/// Executes the secure sum of product on the MPC helper side. Each helper will proceed with
/// their part, eventually producing 2/3 shares of the product and that is what this function
/// returns.
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
pub async fn sum_of_products<C, F>(
    ctx: C,
    record_id: RecordId,
    a: &[Replicated<F>],
    b: &[Replicated<F>],
) -> Result<Replicated<F>, Error>
where
    C: Context,
    F: Field,
{
    assert_eq!(a.len(), b.len());
    let vec_len = a.len();

    // generate shared randomness.
    let prss = ctx.prss();
    let (s0, s1): (F, F) = prss.generate_fields(record_id);
    let role = ctx.role();

    // compute the value (d_i) we want to send to the right helper (i+1)
    let mut right_sops: F = -s0;

    for i in 0..vec_len {
        right_sops += a[i].left() * b[i].right() + a[i].right() * b[i].left();
    }

    // notify helper on the right that we've computed our value
    ctx.send_channel(role.peer(Direction::Right))
        .send(record_id, right_sops)
        .await?;

    // Sleep until helper on the left sends us their (d_i-1) value
    let left_sops: F = ctx
        .recv_channel(role.peer(Direction::Left))
        .receive(record_id)
        .await?;

    // now we are ready to construct the result - 2/3 secret shares of a * b.
    let mut lhs = left_sops + s0;
    let mut rhs = right_sops + s1;

    for i in 0..vec_len {
        lhs += a[i].left() * b[i].left();
        rhs += a[i].right() * b[i].right();
    }
    Ok(Replicated::new(lhs, rhs))
}

#[cfg(all(test, unit_test))]
mod test {
    use super::sum_of_products;
    use crate::{
        ff::{Field, Fp31},
        protocol::{context::Context, RecordId},
        rand::{thread_rng, Rng},
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::default();
        assert_eq!(11, sop_sync(&world, &[7], &[6]).await);
        assert_eq!(3, sop_sync(&world, &[6, 2], &[5, 2]).await);
        assert_eq!(28, sop_sync(&world, &[5, 3], &[5, 1]).await);
        assert_eq!(16, sop_sync(&world, &[7, 1, 4], &[1, 1, 2]).await);
        assert_eq!(13, sop_sync(&world, &[0, 4, 7, 2], &[14, 0, 6, 1]).await);
        assert_eq!(
            15,
            sop_sync(&world, &[7, 5, 4, 2, 1], &[10, 3, 2, 3, 9]).await
        );
    }

    #[tokio::test]
    pub async fn simple() {
        const MULTI_BIT_LEN: usize = 10;
        let world = TestWorld::default();

        let mut rng = thread_rng();

        let (mut av, mut bv) = (
            Vec::with_capacity(MULTI_BIT_LEN),
            Vec::with_capacity(MULTI_BIT_LEN),
        );
        let mut expected = Fp31::ZERO;
        for _ in 0..MULTI_BIT_LEN {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();
            expected += a * b;
            av.push(a);
            bv.push(b);
        }

        let res = world
            .semi_honest((av.into_iter(), bv.into_iter()), |ctx, (a, b)| async move {
                sum_of_products(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    a.as_slice(),
                    b.as_slice(),
                )
                .await
                .unwrap()
            })
            .await;

        assert_eq!(expected, res.reconstruct());
    }

    async fn sop_sync(world: &TestWorld, a: &[u128], b: &[u128]) -> u128 {
        let a: Vec<_> = a.iter().map(|x| Fp31::try_from(*x).unwrap()).collect();
        let b: Vec<_> = b.iter().map(|x| Fp31::try_from(*x).unwrap()).collect();

        let result = world
            .semi_honest((a.into_iter(), b.into_iter()), |ctx, (a, b)| async move {
                sum_of_products(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    a.as_slice(),
                    b.as_slice(),
                )
                .await
                .unwrap()
            })
            .await;

        result.reconstruct().as_u128()
    }
}
