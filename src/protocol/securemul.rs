use super::UniqueStepId;
use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::{fabric::Network, messaging::Gateway, Direction};
use crate::protocol::{prss::IndexedSharedRandomness, RecordId};
use crate::secret_sharing::Replicated;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
use std::sync::Arc;
use thiserror::Error;

/// A message sent by each helper when they've multiplied their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct DValue<F> {
    d: F,
}

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
#[derive(Debug)]
pub struct SecureMul<'a, N> {
    prss: Arc<IndexedSharedRandomness>,
    gateway: &'a Gateway<N>,
    step: &'a UniqueStepId,
    record_id: RecordId,
}

impl<'a, N: Network> SecureMul<'a, N> {
    pub fn new(
        prss: Arc<IndexedSharedRandomness>,
        gateway: &'a Gateway<N>,
        step: &'a UniqueStepId,
        record_id: RecordId,
    ) -> Self {
        Self {
            prss,
            gateway,
            step,
            record_id,
        }
    }

    /// Executes the secure multiplication on the MPC helper side. Each helper will proceed with
    /// their part, eventually producing 2/3 shares of the product and that is what this function
    /// returns.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    pub async fn execute<F: Field>(
        self,
        a: Replicated<F>,
        b: Replicated<F>,
    ) -> Result<Replicated<F>, BoxError> {
        let channel = self.gateway.mesh(self.step);

        // generate shared randomness.
        let (s0, s1) = self.prss.generate_fields(self.record_id);

        // compute the value (d_i) we want to send to the right helper (i+1)
        let (a0, a1) = a.as_tuple();
        let (b0, b1) = b.as_tuple();
        let right_d = a0 * b1 + a1 * b0 - s0;

        // notify helper on the right that we've computed our value
        channel
            .send(
                channel.identity().peer(Direction::Right),
                self.record_id,
                DValue { d: right_d },
            )
            .await?;

        // Sleep until helper on the left sends us their (d_i-1) value
        let DValue { d: left_d } = channel
            .receive(channel.identity().peer(Direction::Left), self.record_id)
            .await?;

        // now we are ready to construct the result - 2/3 secret shares of a * b.
        let lhs = a0 * b0 + left_d + s0;
        let rhs = a1 * b1 + right_d + s1;

        Ok(Replicated::new(lhs, rhs))
    }
}

#[derive(Error, Debug)]
pub enum Error {}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::field::{Field, Fp31};
    use crate::helpers::fabric::Network;
    use crate::protocol::{context::ProtocolContext, QueryId, RecordId};
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::{
        fabric::InMemoryEndpoint, logging, make_contexts, make_world, share,
        validate_and_reconstruct, TestWorld,
    };
    use futures_util::future::join_all;
    use rand::rngs::mock::StepRng;
    use rand::RngCore;
    use std::sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    };

    #[tokio::test]
    async fn basic() -> Result<(), BoxError> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rand = StepRng::new(1, 1);

        assert_eq!(30, multiply_sync(&context, 6, 5, &mut rand).await?);
        assert_eq!(25, multiply_sync(&context, 5, 5, &mut rand).await?);
        assert_eq!(7, multiply_sync(&context, 7, 1, &mut rand).await?);
        assert_eq!(0, multiply_sync(&context, 0, 14, &mut rand).await?);
        assert_eq!(8, multiply_sync(&context, 7, 10, &mut rand).await?);
        assert_eq!(4, multiply_sync(&context, 5, 7, &mut rand).await?);
        assert_eq!(1, multiply_sync(&context, 16, 2, &mut rand).await?);

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
        async fn mul<F: Field>(
            v: (ProtocolContext<'_, Arc<InMemoryEndpoint>>, MulArgs<F>),
        ) -> Replicated<F> {
            let (ctx, (a, b)) = v;
            ctx.multiply(RecordId::from(0))
                .await
                .execute(a, b)
                .await
                .unwrap()
        }

        logging::setup();

        let world = make_world(QueryId);
        let contexts = make_contexts(&world);
        let mut rand = StepRng::new(1, 1);

        let mut multiplications = Vec::new();

        for step in 1..10_u8 {
            let a = share(Fp31::from(4_u128), &mut rand);
            let b = share(Fp31::from(3_u128), &mut rand);

            // there is something weird going on the compiler's side. I don't see why we need
            // to use async move as `i` is Copy + Clone, but compiler complains about it not living
            // long enough
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

    async fn multiply_sync<R: RngCore, N: Network>(
        context: &[ProtocolContext<'_, N>; 3],
        a: u8,
        b: u8,
        rng: &mut R,
    ) -> Result<u8, BoxError> {
        assert!(a < Fp31::PRIME);
        assert!(b < Fp31::PRIME);

        let a = Fp31::from(u128::from(a));
        let b = Fp31::from(u128::from(b));

        thread_local! {
            static INDEX: AtomicU32 = AtomicU32::default();
        }

        let record_id = INDEX.with(|i| i.fetch_add(1, Ordering::Release)).into();

        let a = share(a, rng);
        let b = share(b, rng);

        let result_shares = tokio::try_join!(
            context[0].multiply(record_id).await.execute(a[0], b[0]),
            context[1].multiply(record_id).await.execute(a[1], b[1]),
            context[2].multiply(record_id).await.execute(a[2], b[2]),
        )?;

        Ok(validate_and_reconstruct(result_shares).into())
    }
}
