use crate::error::BoxError;
use crate::ff::Field;
use crate::helpers::Direction;
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use std::fmt::Debug;

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
#[derive(Debug)]
pub struct SecureMul<'a, F> {
    ctx: ProtocolContext<'a, F>,
    record_id: RecordId,
}

impl<'a, F: Field> SecureMul<'a, F> {
    pub fn new(ctx: ProtocolContext<'a, F>, record_id: RecordId) -> Self {
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
        a: Replicated<F>,
        b: Replicated<F>,
    ) -> Result<Replicated<F>, BoxError> {
        let channel = self.ctx.mesh();

        // generate shared randomness.
        let prss = self.ctx.prss();
        let (s0, s1) = prss.generate_fields(self.record_id);

        // compute the value (d_i) we want to send to the right helper (i+1)
        let right_d = a.left() * b.right() + a.right() * b.left() - s0;

        // notify helper on the right that we've computed our value
        channel
            .send(
                self.ctx.role().peer(Direction::Right),
                self.record_id,
                right_d,
            )
            .await?;

        // Sleep until helper on the left sends us their (d_i-1) value
        let left_d = channel
            .receive(self.ctx.role().peer(Direction::Left), self.record_id)
            .await?;

        // now we are ready to construct the result - 2/3 secret shares of a * b.
        let lhs = a.left() * b.left() + left_d + s0;
        let rhs = a.right() * b.right() + right_d + s1;

        Ok(Replicated::new(lhs, rhs))
    }
}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::ff::{Field, Fp31};
    use crate::protocol::{context::ProtocolContext, QueryId, RecordId};
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::{
        make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
    };
    use futures_util::future::join_all;
    use rand::rngs::mock::StepRng;
    use rand::RngCore;
    use std::sync::atomic::{AtomicU32, Ordering};

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rand = StepRng::new(1, 1);

        assert_eq!(30, multiply_sync(&context, "1", 6, 5, &mut rand).await?);
        assert_eq!(25, multiply_sync(&context, "2", 5, 5, &mut rand).await?);
        assert_eq!(7, multiply_sync(&context, "3", 7, 1, &mut rand).await?);
        assert_eq!(0, multiply_sync(&context, "4", 0, 14, &mut rand).await?);
        assert_eq!(8, multiply_sync(&context, "5", 7, 10, &mut rand).await?);
        assert_eq!(4, multiply_sync(&context, "6", 5, 7, &mut rand).await?);
        assert_eq!(1, multiply_sync(&context, "7", 16, 2, &mut rand).await?);

        Ok(())
    }

    /// This test ensures that many secure multiplications can run concurrently as long as
    /// they all have unique id associated with it. Basically it validates
    /// `TestHelper`'s ability to distinguish messages of the same type sent towards helpers
    /// executing multiple same type protocols
    #[tokio::test]
    #[allow(clippy::cast_possible_truncation)]
    pub async fn concurrent_mul() {
        type MulArgs<F> = (Replicated<F>, Replicated<F>);
        async fn mul<F: Field>(v: (ProtocolContext<'_, F>, MulArgs<F>)) -> Replicated<F> {
            let (ctx, (a, b)) = v;
            ctx.multiply(RecordId::from(1_u32))
                .execute(a, b)
                .await
                .unwrap()
        }

        let world = make_world(QueryId);
        let contexts = make_contexts::<Fp31>(&world);
        let mut rand = StepRng::new(1, 1);

        let mut multiplications = Vec::new();

        for step in 1..10_u8 {
            let a = share(Fp31::from(4_u128), &mut rand);
            let b = share(Fp31::from(3_u128), &mut rand);

            let step_name = format!("step{}", step);
            let f = join_all(
                contexts
                    .iter()
                    .map(|ctx| ctx.narrow(&step_name))
                    .zip(std::iter::zip(a, b))
                    .map(mul),
            );
            multiplications.push(f);
        }

        let results = join_all(multiplications).await;
        for shares in results {
            assert_eq!(
                Fp31::from(12_u128),
                validate_and_reconstruct((shares[0], shares[1], shares[2]))
            );
        }
    }

    async fn multiply_sync<R: RngCore, F: Field>(
        context: &[ProtocolContext<'_, F>; 3],
        narrowed_context_str: &str,
        a: u8,
        b: u8,
        rng: &mut R,
    ) -> Result<u128, BoxError> {
        let a = F::from(u128::from(a));
        let b = F::from(u128::from(b));

        thread_local! {
            static INDEX: AtomicU32 = AtomicU32::default();
        }

        let record_id = INDEX.with(|i| i.fetch_add(1, Ordering::Release)).into();

        let a = share(a, rng);
        let b = share(b, rng);

        let result_shares = tokio::try_join!(
            context[0]
                .narrow(narrowed_context_str)
                .multiply(record_id)
                .execute(a[0], b[0]),
            context[1]
                .narrow(narrowed_context_str)
                .multiply(record_id)
                .execute(a[1], b[1]),
            context[2]
                .narrow(narrowed_context_str)
                .multiply(record_id)
                .execute(a[2], b[2]),
        )?;

        Ok(validate_and_reconstruct(result_shares).as_u128())
    }
}
