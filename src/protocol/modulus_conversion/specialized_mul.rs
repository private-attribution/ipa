use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, Role},
    protocol::{context::ProtocolContext, RecordId},
    secret_sharing::Replicated,
};
use crate::protocol::context::SemiHonestProtocolContext;

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
pub async fn multiply_two_shares_mostly_zeroes<F: Field>(
    ctx: SemiHonestProtocolContext<'_, F>,
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
#[allow(dead_code)]
pub async fn multiply_one_share_mostly_zeroes<F: Field>(
    ctx: SemiHonestProtocolContext<'_, F>,
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

#[cfg(test)]
pub mod tests {
    use std::iter::zip;

    use crate::error::Error;
    use crate::ff::{Field, Fp31};
    use crate::protocol::{
        modulus_conversion::specialized_mul::{
            multiply_one_share_mostly_zeroes, multiply_two_shares_mostly_zeroes,
        },
        QueryId, RecordId,
    };
    use crate::secret_sharing::Replicated;
    use crate::test_fixture::{
        make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use crate::protocol::context::ProtocolContext;

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
                multiply_two_shares_mostly_zeroes(
                    context[0].bind(record_id),
                    record_id,
                    &Replicated::new(a, Fp31::ZERO),
                    &Replicated::new(Fp31::ZERO, b),
                ),
                multiply_two_shares_mostly_zeroes(
                    context[1].bind(record_id),
                    record_id,
                    &Replicated::new(Fp31::ZERO, Fp31::ZERO),
                    &Replicated::new(b, Fp31::ZERO),
                ),
                multiply_two_shares_mostly_zeroes(
                    context[2].bind(record_id),
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
                multiply_two_shares_mostly_zeroes(
                    context[0].bind(record_id),
                    record_id,
                    &a_shares[i][0],
                    &b_shares[i][0],
                ),
                multiply_two_shares_mostly_zeroes(
                    context[1].bind(record_id),
                    record_id,
                    &a_shares[i][1],
                    &b_shares[i][1],
                ),
                multiply_two_shares_mostly_zeroes(
                    context[2].bind(record_id),
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
                multiply_one_share_mostly_zeroes(
                    context[0].bind(record_id),
                    record_id,
                    &a_shares[0],
                    &Replicated::new(Fp31::ZERO, Fp31::ZERO),
                ),
                multiply_one_share_mostly_zeroes(
                    context[1].bind(record_id),
                    record_id,
                    &a_shares[1],
                    &Replicated::new(Fp31::ZERO, b),
                ),
                multiply_one_share_mostly_zeroes(
                    context[2].bind(record_id),
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
                multiply_one_share_mostly_zeroes(
                    context[0].bind(record_id),
                    record_id,
                    &a_shares[i][0],
                    &b_shares[i][0],
                ),
                multiply_one_share_mostly_zeroes(
                    context[1].bind(record_id),
                    record_id,
                    &a_shares[i][1],
                    &b_shares[i][1],
                ),
                multiply_one_share_mostly_zeroes(
                    context[2].bind(record_id),
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
