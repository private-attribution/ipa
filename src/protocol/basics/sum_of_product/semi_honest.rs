use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Direction;
#[cfg(feature = "no-prss")]
use crate::protocol::no_prss::SharedRandomness;
#[cfg(not(feature = "no-prss"))]
use crate::protocol::use_prss::SharedRandomness;
use crate::protocol::{
    context::{Context, SemiHonestContext},
    RecordId,
};
use crate::secret_sharing::Replicated;

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
pub async fn sum_of_products<F>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    pairs: &[(&Replicated<F>, &Replicated<F>)],
) -> Result<Replicated<F>, Error>
where
    F: Field,
{
    let channel = ctx.mesh();

    // generate shared randomness.
    let prss = ctx.prss();
    let (s0, s1): (F, F) = prss.generate_fields(record_id);
    let role = ctx.role();

    // compute the value (d_i) we want to send to the right helper (i+1)
    let mut right_sops: F = -s0;

    for pair in pairs.iter() {
        right_sops += pair.0.left() * pair.1.right() + pair.0.right() * pair.1.left();
    }

    // notify helper on the right that we've computed our value
    channel
        .send(role.peer(Direction::Right), record_id, right_sops)
        .await?;

    // Sleep until helper on the left sends us their (d_i-1) value
    let left_sops: F = channel
        .receive(role.peer(Direction::Left), record_id)
        .await?;

    // now we are ready to construct the result - 2/3 secret shares of a * b.
    let mut lhs = left_sops + s0;
    let mut rhs = right_sops + s1;

    for pair in pairs.iter() {
        lhs += pair.0.left() * pair.1.left();
        rhs += pair.0.right() * pair.1.right();
    }
    Ok(Replicated::new(lhs, rhs))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod test {
    use crate::rand::Rng;

    use crate::rand::thread_rng;

    use crate::ff::{Field, Fp31};
    use crate::protocol::basics::sum_of_product::SecureSop;
    use crate::protocol::RecordId;
    use crate::test_fixture::{Reconstruct, Runner, TestWorld};

    #[tokio::test]
    async fn basic() {
        let world = TestWorld::new().await;
        assert_eq!(11, sop_sync::<Fp31>(&world, &[7], &[6]).await);
        assert_eq!(3, sop_sync::<Fp31>(&world, &[6, 2], &[5, 2]).await);
        assert_eq!(28, sop_sync::<Fp31>(&world, &[5, 3], &[5, 1]).await);
        assert_eq!(16, sop_sync::<Fp31>(&world, &[7, 1, 4], &[1, 1, 2]).await);
        assert_eq!(
            13,
            sop_sync::<Fp31>(&world, &[0, 4, 7, 2], &[14, 0, 6, 1]).await
        );
        assert_eq!(
            15,
            sop_sync::<Fp31>(&world, &[7, 5, 4, 2, 1], &[10, 3, 2, 3, 9]).await
        );
    }

    #[tokio::test]
    pub async fn simple() {
        const MULTI_BIT_LEN: usize = 10;
        let world = TestWorld::new().await;

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
            .semi_honest((av, bv), |ctx, (a_share, b_share)| async move {
                let mut pairs = Vec::with_capacity(a_share.len());
                for i in 0..a_share.len() {
                    pairs.push((&a_share[i], &b_share[i]));
                }
                ctx.sum_of_products(RecordId::from(0), pairs.as_slice())
                    .await
                    .unwrap()
            })
            .await;

        assert_eq!(expected, res.reconstruct());
    }

    async fn sop_sync<F>(world: &TestWorld, a: &[u128], b: &[u128]) -> u128
    where
        F: Field,
        (F, F): Sized,
    {
        let a: Vec<_> = a.iter().map(|x| Fp31::from(*x)).collect();
        let b: Vec<_> = b.iter().map(|x| Fp31::from(*x)).collect();

        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                let mut pairs = Vec::with_capacity(a_share.len());
                for i in 0..a_share.len() {
                    pairs.push((&a_share[i], &b_share[i]));
                }

                ctx.sum_of_products(RecordId::from(0), pairs.as_slice())
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct().as_u128()
    }
}
