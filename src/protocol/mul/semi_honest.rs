use crate::error::Error;
use crate::ff::Field;
use crate::helpers::{Direction, Role};
use crate::protocol::{context::ProtocolContext, RecordId};
use crate::secret_sharing::Replicated;
use std::fmt::Debug;

/// IKHC multiplication protocol
/// for use with replicated secret sharing over some field F.
/// K. Chida, K. Hamada, D. Ikarashi, R. Kikuchi, and B. Pinkas. High-throughput secure AES computation. In WAHC@CCS 2018, pp. 13–24, 2018
#[derive(Debug)]
pub struct SecureMul<'a, F: Field> {
    ctx: ProtocolContext<'a, Replicated<F>, F>,
    record_id: RecordId,
}

impl<'a, F: Field> SecureMul<'a, F> {
    #[must_use]
    pub fn new(ctx: ProtocolContext<'a, Replicated<F>, F>, record_id: RecordId) -> Self {
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

    /// A highly specialized variant of the IKHC multiplication protocol which is only valid
    /// in the case where 4 of the 6 shares are zero.
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
    /// Helper 1 has shares (a, 0) and (0, b)
    /// Helper 2 has shares (0, 0) and (b, 0)
    /// Helper 3 has shares (0, a) and (0, 0)
    ///
    /// But in this case, `d_2` and `d_3` are publicly known to all the helper parties
    /// and can be replaced with constants, e.g. 0. Therefore, these do not need to be sent.
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    #[allow(dead_code)]
    pub async fn multiply_two_shares_mostly_zeroes(
        self,
        a: &Replicated<F>,
        b: &Replicated<F>,
    ) -> Result<Replicated<F>, Error> {
        match self.ctx.role() {
            Role::H1 => {
                let prss = self.ctx.prss();
                let (s_3_1, _) = prss.generate_fields(self.record_id);

                // d_1 = a_1 * b_2 + a_2 * b_1 - s_3,1
                // d_1 = a_1 * b_2 + 0 * 0 - s_3,1
                let (a_1, a_2) = a.as_tuple();
                let (b_1, b_2) = b.as_tuple();
                debug_assert!(a_2 == F::ZERO);
                debug_assert!(b_1 == F::ZERO);

                let d_1 = a_1 * b_2 - s_3_1;

                // notify helper on the right that we've computed our value
                let channel = self.ctx.mesh();
                channel
                    .send(self.ctx.role().peer(Direction::Right), self.record_id, d_1)
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
                let channel = self.ctx.mesh();
                let d_1 = channel
                    .receive(self.ctx.role().peer(Direction::Left), self.record_id)
                    .await?;

                Ok(Replicated::new(d_1, F::ZERO))
            }
            Role::H3 => {
                // d_3 = a_3 * b_1 + a_1 * b_3 - s_2,3
                // d_3 = 0 * 0 + a * 0 - s_2,3
                // d_3 = s_2,3
                // d_3 is a constant, known in advance. So we can replace it with zero
                // And there is no need to send it.

                let prss = self.ctx.prss();
                let (_, s_3_1) = prss.generate_fields(self.record_id);

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
    #[allow(dead_code)]
    pub async fn multiply_one_share_mostly_zeroes(
        self,
        a: &Replicated<F>,
        b: &Replicated<F>,
    ) -> Result<Replicated<F>, Error> {
        let prss = self.ctx.prss();
        let (s_left, s_right) = prss.generate_fields(self.record_id);

        match self.ctx.role() {
            Role::H1 => {
                // d_1 = a_1 * b_2 + a_2 * b_1 - s_3,1
                // d_1 = a_1 * 0 + a_2 * 0 - s_3,1
                // d_1 = - s_3,1
                // d_2 is a constant, known in advance. So we can replace it with zero
                // And there is no need to send it.

                // Sleep until helper on the left sends us their (d_i-1) value
                let channel = self.ctx.mesh();
                let d_3 = channel
                    .receive(self.ctx.role().peer(Direction::Left), self.record_id)
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
                let channel = self.ctx.mesh();
                channel
                    .send(self.ctx.role().peer(Direction::Right), self.record_id, d_2)
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
                let channel = self.ctx.mesh();
                channel
                    .send(self.ctx.role().peer(Direction::Right), self.record_id, d_3)
                    .await?;

                // Sleep until helper on the left sends us their (d_i-1) value
                let d_2 = channel
                    .receive(self.ctx.role().peer(Direction::Left), self.record_id)
                    .await?;

                Ok(Replicated::new(a_3 * b_3 + d_2 + s_left, d_3))
            }
        }
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
                            .bind(record_id)
                            .multiply(record_id, &a_shares[0], &b_shares[0]),
                        ctx[1]
                            .bind(record_id)
                            .multiply(record_id, &a_shares[1], &b_shares[1]),
                        ctx[2]
                            .bind(record_id)
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
        context: [ProtocolContext<'_, Replicated<F>, F>; 3],
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

    #[tokio::test]
    async fn specialized_1_sequence() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        for i in 0..10_u32 {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();

            let record_id = RecordId::from(i);

            let result_shares = try_join_all([
                context[0]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(
                        record_id,
                        &Replicated::new(a, Fp31::ZERO),
                        &Replicated::new(Fp31::ZERO, b),
                    ),
                context[1]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(
                        record_id,
                        &Replicated::new(Fp31::ZERO, Fp31::ZERO),
                        &Replicated::new(b, Fp31::ZERO),
                    ),
                context[2]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(
                        record_id,
                        &Replicated::new(Fp31::ZERO, a),
                        &Replicated::new(Fp31::ZERO, Fp31::ZERO),
                    ),
            ])
            .await?;

            let result =
                validate_and_reconstruct(&result_shares[0], &result_shares[1], &result_shares[2]);
            assert_eq!(result, a * b);
        }

        Ok(())
    }

    #[tokio::test]
    async fn specialized_1_parallel() -> Result<(), Error> {
        const ROUNDS: usize = 10;
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        let mut inputs = Vec::with_capacity(ROUNDS);
        let mut a_shares = Vec::with_capacity(ROUNDS);
        let mut b_shares = Vec::with_capacity(ROUNDS);
        let mut futures = Vec::with_capacity(ROUNDS);

        for _ in 0..ROUNDS {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();

            inputs.push((a, b));

            a_shares.push([
                Replicated::new(a, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, a),
            ]);
            b_shares.push([
                Replicated::new(Fp31::ZERO, b),
                Replicated::new(b, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
            ]);
        }
        for i in 0..ROUNDS {
            let record_id = RecordId::from(i);
            futures.push(try_join_all([
                context[0]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(record_id, &a_shares[i][0], &b_shares[i][0]),
                context[1]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(record_id, &a_shares[i][1], &b_shares[i][1]),
                context[2]
                    .bind(record_id)
                    .multiply_two_shares_mostly_zeroes(record_id, &a_shares[i][2], &b_shares[i][2]),
            ]));
        }

        let results = try_join_all(futures).await?;

        for (input, result) in zip(inputs, results) {
            let multiplication_output =
                validate_and_reconstruct(&result[0], &result[1], &result[2]);

            assert_eq!(multiplication_output, input.0 * input.1);
        }

        Ok(())
    }

    #[tokio::test]
    async fn specialized_2_sequence() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        for i in 0..10_u32 {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();

            let a_shares = share(a, &mut rng);

            let record_id = RecordId::from(i);

            let result_shares = try_join_all([
                context[0].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[0],
                    &Replicated::new(Fp31::ZERO, Fp31::ZERO),
                ),
                context[1].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[1],
                    &Replicated::new(Fp31::ZERO, b),
                ),
                context[2].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[2],
                    &Replicated::new(b, Fp31::ZERO),
                ),
            ])
            .await?;

            let result =
                validate_and_reconstruct(&result_shares[0], &result_shares[1], &result_shares[2]);

            assert_eq!(result, a * b);
        }

        Ok(())
    }

    #[tokio::test]
    async fn specialized_2_parallel() -> Result<(), Error> {
        const ROUNDS: usize = 10;
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        let mut inputs = Vec::with_capacity(ROUNDS);
        let mut a_shares = Vec::with_capacity(ROUNDS);
        let mut b_shares = Vec::with_capacity(ROUNDS);
        let mut futures = Vec::with_capacity(ROUNDS);

        for _ in 0..ROUNDS {
            let a = rng.gen::<Fp31>();
            let b = rng.gen::<Fp31>();

            inputs.push((a, b));

            a_shares.push(share(a, &mut rng));
            b_shares.push([
                Replicated::new(Fp31::ZERO, Fp31::ZERO),
                Replicated::new(Fp31::ZERO, b),
                Replicated::new(b, Fp31::ZERO),
            ]);
        }

        for i in 0..ROUNDS {
            let record_id = RecordId::from(i);
            futures.push(try_join_all([
                context[0].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[i][0],
                    &b_shares[i][0],
                ),
                context[1].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[i][1],
                    &b_shares[i][1],
                ),
                context[2].bind(record_id).multiply_one_share_mostly_zeroes(
                    record_id,
                    &a_shares[i][2],
                    &b_shares[i][2],
                ),
            ]));
        }

        let results = try_join_all(futures).await?;

        for (input, result) in zip(inputs, results) {
            let multiplication_output =
                validate_and_reconstruct(&result[0], &result[1], &result[2]);

            assert_eq!(multiplication_output, input.0 * input.1);
        }

        Ok(())
    }
}
