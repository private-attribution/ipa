use crate::{
    error::BoxError,
    field::Field,
    helpers::{fabric::Network, Direction},
    protocol::{check_zero::check_zero, context::ProtocolContext, reveal::reveal, RecordId},
    secret_sharing::Replicated,
};
use futures::future::try_join;

use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've computed one share of the result
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct UValue<F> {
    payload: F,
}

#[allow(dead_code)]
pub struct SecurityValidator<'a, F, N> {
    internally_indexed_ctx: ProtocolContext<'a, N>,
    r_share: Replicated<F>,
    u: F,
    w: F,
}

impl<'a, F: Field, N: Network> SecurityValidator<'a, F, N> {
    #[allow(dead_code)]
    pub fn new(ctx: &ProtocolContext<'a, N>) -> SecurityValidator<'a, F, N> {
        let internally_indexed_ctx = ctx.narrow(&"ValidationInternalIndexed".to_string());
        let prss = internally_indexed_ctx.prss();

        let r_share = prss.generate_replicated(RecordId::from(0));
        let (u_left, u_right): (F, F) = prss.generate_fields(RecordId::from(1));
        let (w_left, w_right): (F, F) = prss.generate_fields(RecordId::from(2));

        SecurityValidator {
            internally_indexed_ctx,
            r_share,
            u: u_right - u_left,
            w: w_right - w_left,
        }
    }

    #[allow(dead_code)]
    fn compute_dot_product_contribution(a: Replicated<F>, b: Replicated<F>) -> F {
        let (a_left, a_right) = a.as_tuple();
        let (b_left, b_right) = b.as_tuple();
        (a_left + a_right) * (b_left + b_right) - a_right * b_right
    }

    #[allow(dead_code)]
    fn accumulate_macs(
        &mut self,
        ctx: &ProtocolContext<'_, N>,
        record_id: RecordId,
        x: Replicated<F>,
        rx: Replicated<F>,
    ) {
        // The helpers need to use the same shared randomness to generate the random constant used to validate a given multiplication.
        // This is a bit tricky, because we cannot count on the multiplications being executed in the same order across all the helpers.
        // The easiest way is to just narrow the context used to perform the multiplication, and then re-use the same record_id.
        // This ensures that when the helpers all go to validate the multiplication: "1/foo/bar/baz", they all use the prss from "1/foo/bar/baz/validate".
        // That way, we don't need to worry about the order in which the multiplications are executed.
        let prss = ctx.narrow(&"validate".to_string()).prss();
        let random_constant = prss.generate_replicated(record_id);

        self.u += Self::compute_dot_product_contribution(random_constant, rx);
        self.w += Self::compute_dot_product_contribution(random_constant, x);
    }

    ///
    /// For each input, `x` of the arithmetic circuit, call this method to obtain
    /// a secret-sharing of `r * x`.
    /// This will also affect the information theoretic MAC that is eventually validated
    /// once the circuit is complete and before outputs are revealed
    ///
    #[allow(dead_code)]
    pub async fn input(
        &mut self,
        ctx: &ProtocolContext<'_, N>,
        record_id: RecordId,
        x: Replicated<F>,
    ) -> Result<Replicated<F>, BoxError> {
        let rx = ctx
            .narrow(&"validate_input".to_string())
            .multiply(record_id)
            .await
            .execute(self.r_share, x)
            .await?;

        self.accumulate_macs(ctx, record_id, x, rx);
        Ok(rx)
    }

    ///
    /// Each time a multiplication is performed, it must be performed twice, in order to compute both the desired result: `z`,
    /// as well as the result `r * z`. Once these two values are obtained, they should be passed to this function.
    #[allow(dead_code)]
    pub fn validate_multiplication_output(
        &mut self,
        ctx: &ProtocolContext<'_, N>,
        record_id: RecordId,
        z: Replicated<F>,
        rz: Replicated<F>,
    ) {
        self.accumulate_macs(ctx, record_id, z, rz);
    }

    #[allow(dead_code)]
    pub async fn validate(&self) -> Result<bool, BoxError> {
        let record_3 = RecordId::from(3);
        let record_4 = RecordId::from(4);
        let record_5 = RecordId::from(5);
        let record_6 = RecordId::from(6);

        // send our `u_i+1` value to the helper on the right
        let channel = self.internally_indexed_ctx.mesh();
        try_join(
            channel.send(
                self.internally_indexed_ctx.role().peer(Direction::Right),
                record_3,
                UValue { payload: self.u },
            ),
            channel.send(
                self.internally_indexed_ctx.role().peer(Direction::Right),
                record_4,
                UValue { payload: self.w },
            ),
        )
        .await?;

        // receive `u_i` value from helper to the left
        let (u_left_struct, w_left_struct): (UValue<F>, UValue<F>) = try_join(
            channel.receive(
                self.internally_indexed_ctx.role().peer(Direction::Left),
                record_3,
            ),
            channel.receive(
                self.internally_indexed_ctx.role().peer(Direction::Left),
                record_4,
            ),
        )
        .await?;

        let u_left = u_left_struct.payload;
        let w_left = w_left_struct.payload;

        let u_share = Replicated::new(u_left, self.u);
        let w_share = Replicated::new(w_left, self.w);

        // This should probably be done in parallel with the futures above
        let r = reveal(
            self.internally_indexed_ctx.narrow(&"hack1".to_string()),
            record_5,
            self.r_share,
        )
        .await?;
        let t = u_share - (w_share * r);

        check_zero(
            self.internally_indexed_ctx.narrow(&"hack2".to_string()),
            record_6,
            t,
        )
        .await
    }
}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::field::Fp31;
    use crate::protocol::{malicious::SecurityValidator, QueryId, RecordId};
    use crate::test_fixture::{logging, make_contexts, make_world, share, TestWorld};
    use futures::future::try_join_all;
    use proptest::prelude::Rng;

    #[tokio::test]
    async fn test_simplest_circuit() -> Result<(), BoxError> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = rand::thread_rng();

        let a = Fp31::from(rng.gen::<u128>());
        let b = Fp31::from(rng.gen::<u128>());

        let a_shares = share(a, &mut rng);
        let b_shares = share(b, &mut rng);

        let futures = (0..3).into_iter().zip(context).map(|(i, ctx)| async move {
            let mut v = SecurityValidator::new(&ctx);

            let a_record_narrowed_context = ctx.narrow(&"hack_1".to_string());
            let ra = v
                .input(&a_record_narrowed_context, RecordId::from(0), a_shares[i])
                .await?;

            let b_record_narrowed_context = ctx.narrow(&"hack_2".to_string());
            let _rb = v
                .input(&b_record_narrowed_context, RecordId::from(1), b_shares[i])
                .await?;

            let mult_step = "Mult".to_string();
            let mult_context = a_record_narrowed_context.narrow(&mult_step);

            let ab = mult_context
                .multiply(RecordId::from(0))
                .await
                .execute(a_shares[i], b_shares[i])
                .await?;

            let double_check_mult_step = "DoubleCheck".to_string();
            let double_check_mult_context = mult_context.narrow(&double_check_mult_step);

            let rab = double_check_mult_context
                .multiply(RecordId::from(0))
                .await
                .execute(ra, b_shares[i])
                .await?;

            v.validate_multiplication_output(
                &double_check_mult_context,
                RecordId::from(0),
                ab,
                rab,
            );

            v.validate().await
        });

        let results = try_join_all(futures).await?;

        for result in results {
            assert!(result);
        }
        Ok(())
    }

    #[tokio::test]
    async fn test_complex_circuit() -> Result<(), BoxError> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = rand::thread_rng();

        let mut shared_inputs = [
            Vec::with_capacity(100),
            Vec::with_capacity(100),
            Vec::with_capacity(100),
        ];
        for _ in 0..100 {
            let x = Fp31::from(rng.gen::<u128>());
            let x_shared = share(x, &mut rng);
            shared_inputs[0].push(x_shared[0]);
            shared_inputs[1].push(x_shared[1]);
            shared_inputs[2].push(x_shared[2]);
        }

        let futures =
            context
                .into_iter()
                .zip(shared_inputs)
                .map(|(ctx, input_shares)| async move {
                    let mut sv = SecurityValidator::new(&ctx);

                    let mut processed_inputs = Vec::with_capacity(100);
                    for i in 0..100 {
                        let step = format!("Record_{}", i);
                        let record_id = RecordId::from(i);
                        let record_narrowed_ctx = ctx.narrow(&step);

                        let x = input_shares[usize::try_from(i).unwrap()];
                        let rx = sv.input(&record_narrowed_ctx, record_id, x).await?;

                        processed_inputs.push((record_narrowed_ctx, record_id, x, rx));
                    }

                    for i in 0..99 {
                        let (narrowed_ctx, record_id, a, ra) = &processed_inputs[i];
                        let (_, _, b, _) = &processed_inputs[i + 1];
                        let step = "MultiplicationStep1".to_string();
                        let mult_context = narrowed_ctx.narrow(&step);

                        let ab = mult_context
                            .multiply(*record_id)
                            .await
                            .execute(*a, *b)
                            .await?;
                        let rab = mult_context
                            .narrow(&"DoubleCheck".to_string())
                            .multiply(*record_id)
                            .await
                            .execute(*ra, *b)
                            .await?;
                        sv.validate_multiplication_output(&mult_context, *record_id, ab, rab);
                    }

                    let is_valid = sv.validate().await?;
                    Ok::<bool, BoxError>(is_valid)
                });

        let results = try_join_all(futures).await?;

        for result in results {
            assert!(result);
        }
        Ok(())
    }
}
