use crate::error::Error;
use crate::ff::Field;
use crate::helpers::Direction;
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use std::fmt::Debug;
use crate::protocol::context::SemiHonestProtocolContext;

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
#[derive(Debug)]
pub struct SecureMul<'a, F: Field> {
    ctx: SemiHonestProtocolContext<'a, F>,
    record_id: RecordId,
}

impl<'a, F: Field> SecureMul<'a, F> {
    #[must_use]
    pub fn new(ctx: SemiHonestProtocolContext<'a, F>, record_id: RecordId) -> Self {
        Self { ctx, record_id }
    }

    /// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
    /// their part, eventually producing 2/3 shares of the product and that is what this function
    /// returns.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    pub async fn execute(
        self,
        a: &Replicated<F>,
        b: &Replicated<F>,
    ) -> Result<Replicated<F>, Error> {
        let channel = self.ctx.mesh();

        // generate shared randomness.
        let prss = self.ctx.prss();
        let (s0, s1) = prss.generate_fields(self.record_id);
        let role = self.ctx.role();

        // compute the value (d_i) we want to send to the right helper (i+1)
        let right_d = a.left() * b.right() + a.right() * b.left() - s0;

        // notify helper on the right that we've computed our value
        channel
            .send(role.peer(Direction::Right), self.record_id, right_d)
            .await?;

        // Sleep until helper on the left sends us their (d_i-1) value
        let left_d = channel
            .receive(role.peer(Direction::Left), self.record_id)
            .await?;

        // now we are ready to construct the result - 2/3 secret shares of a * b.
        let lhs = a.left() * b.left() + left_d + s0;
        let rhs = a.right() * b.right() + right_d + s1;

        Ok(Replicated::new(lhs, rhs))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::error::Error;
    use crate::ff::{Field, Fp31};
    use crate::protocol::mul::SecureMul;
    use crate::protocol::{context::ProtocolContext, QueryId, RecordId};
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::{
        make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use rand::{distributions::Standard, prelude::Distribution, rngs::mock::StepRng, RngCore};
    use std::iter::{repeat, zip};
    use std::sync::atomic::{AtomicU32, Ordering};
    use crate::protocol::context::SemiHonestProtocolContext;

    #[tokio::test]
    async fn basic() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let mut rand = StepRng::new(1, 1);
        let contexts = make_contexts::<Fp31>(&world);

        assert_eq!(30, multiply_sync(contexts.clone(), 6, 5, &mut rand).await?);
        assert_eq!(25, multiply_sync(contexts.clone(), 5, 5, &mut rand).await?);
        assert_eq!(7, multiply_sync(contexts.clone(), 7, 1, &mut rand).await?);
        assert_eq!(0, multiply_sync(contexts.clone(), 0, 14, &mut rand).await?);
        assert_eq!(8, multiply_sync(contexts.clone(), 7, 10, &mut rand).await?);
        assert_eq!(4, multiply_sync(contexts.clone(), 5, 7, &mut rand).await?);
        assert_eq!(1, multiply_sync(contexts.clone(), 16, 2, &mut rand).await?);

        Ok(())
    }

    /// This test ensures that many secure multiplications can run concurrently as long as
    /// they all have unique id associated with it. Basically it validates
    /// `TestHelper`'s ability to distinguish messages of the same type sent towards helpers
    /// executing multiple same type protocols
    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)]
    pub async fn concurrent_mul() {
        let world = make_world(QueryId);
        let contexts = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        let mut expected_outputs = Vec::with_capacity(10);

        let futures: Vec<_> = zip(repeat(contexts), 0..10)
            .map(|(ctx, i)| {
                let a = rng.gen::<Fp31>();
                let b = rng.gen::<Fp31>();
                expected_outputs.push(a * b);

                let a_shares = share(a, &mut rng);
                let b_shares = share(b, &mut rng);

                let record_id = RecordId::from(i);

                async move {
                    try_join_all([
                        ctx[0]
                            .clone()
                            .multiply(record_id, &a_shares[0], &b_shares[0]),
                        ctx[1]
                            .clone()
                            .multiply(record_id, &a_shares[1], &b_shares[1]),
                        ctx[2]
                            .clone()
                            .multiply(record_id, &a_shares[2], &b_shares[2]),
                    ])
                    .await
                }
            })
            .collect();

        let results = try_join_all(futures).await.unwrap();

        for (i, shares) in results.iter().enumerate() {
            assert_eq!(
                expected_outputs[i],
                validate_and_reconstruct(&shares[0], &shares[1], &shares[2])
            );
        }
    }

    async fn multiply_sync<R: RngCore, F: Field>(
        context: [SemiHonestProtocolContext<'_, F>; 3],
        a: u8,
        b: u8,
        rng: &mut R,
    ) -> Result<u128, Error>
    where
        Standard: Distribution<F>,
    {
        let a = F::from(u128::from(a));
        let b = F::from(u128::from(b));

        thread_local! {
            static INDEX: AtomicU32 = AtomicU32::default();
        }

        let [context0, context1, context2] = context;
        let record_id = INDEX.with(|i| i.fetch_add(1, Ordering::Release)).into();

        let a = share(a, rng);
        let b = share(b, rng);

        let result = try_join_all([
            context0.multiply(record_id, &a[0], &b[0]),
            context1.multiply(record_id, &a[1], &b[1]),
            context2.multiply(record_id, &a[2], &b[2]),
        ])
        .await?;

        Ok(validate_and_reconstruct(&result[0], &result[1], &result[2]).as_u128())
    }
}
