use crate::{
    error::{BoxError, Error},
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    #[allow(dead_code)]
    ValidateInput,
    #[allow(dead_code)]
    ValidateMultiplySubstep,
    RevealR,
    CheckZero,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::ValidateInput => "validate_input",
            Self::ValidateMultiplySubstep => "validate_multiply",
            Self::RevealR => "reveal_r",
            Self::CheckZero => "check_zero",
        }
    }
}

#[allow(dead_code)]
pub struct SecurityValidator<'a, F, N> {
    ctx: ProtocolContext<'a, N>,
    r_share: Replicated<F>,
    u: F,
    w: F,
}

impl<'a, F: Field, N: Network> SecurityValidator<'a, F, N> {
    #[allow(dead_code)]
    pub fn new(ctx: ProtocolContext<'a, N>) -> SecurityValidator<'a, F, N> {
        let prss = ctx.prss();

        let r_share = prss.generate_replicated(RecordId::from(0));
        let (u_left, u_right): (F, F) = prss.generate_fields(RecordId::from(1));
        let (w_left, w_right): (F, F) = prss.generate_fields(RecordId::from(2));

        SecurityValidator {
            ctx,
            r_share,
            u: u_right - u_left,
            w: w_right - w_left,
        }
    }

    #[allow(dead_code)]
    pub fn r_share(&self) -> Replicated<F> {
        self.r_share
    }

    #[allow(dead_code)]
    fn compute_dot_product_contribution(a: Replicated<F>, b: Replicated<F>) -> F {
        (a.left() + a.right()) * (b.left() + b.right()) - a.right() * b.right()
    }

    #[allow(dead_code)]
    #[allow(clippy::needless_pass_by_value)]
    pub fn accumulate_macs(
        &mut self,
        ctx: ProtocolContext<'_, N>,
        record_id: RecordId,
        x: Replicated<F>,
        rx: Replicated<F>,
    ) {
        // The helpers need to use the same shared randomness to generate the random constant used to validate a given multiplication.
        // This is a bit tricky, because we cannot count on the multiplications being executed in the same order across all the helpers.
        // The easiest way is to just narrow the context used to perform the multiplication, and then re-use the same record_id.
        // This ensures that when the helpers all go to validate the multiplication: "1/foo/bar/baz", they all use the prss from "1/foo/bar/baz/validate".
        // That way, we don't need to worry about the order in which the multiplications are executed.
        let random_constant = ctx.prss().generate_replicated(record_id);

        self.u += Self::compute_dot_product_contribution(random_constant, rx);
        self.w += Self::compute_dot_product_contribution(random_constant, x);
    }

    #[allow(dead_code)]
    pub async fn validate(&self) -> Result<(), BoxError> {
        let record_3 = RecordId::from(3);
        let record_4 = RecordId::from(4);
        let record_5 = RecordId::from(5);
        let record_6 = RecordId::from(6);

        // send our `u_i+1` value to the helper on the right
        let channel = self.ctx.mesh();
        try_join(
            channel.send(
                self.ctx.role().peer(Direction::Right),
                record_3,
                UValue { payload: self.u },
            ),
            channel.send(
                self.ctx.role().peer(Direction::Right),
                record_4,
                UValue { payload: self.w },
            ),
        )
        .await?;

        // receive `u_i` value from helper to the left
        let (u_left_struct, w_left_struct): (UValue<F>, UValue<F>) = try_join(
            channel.receive(self.ctx.role().peer(Direction::Left), record_3),
            channel.receive(self.ctx.role().peer(Direction::Left), record_4),
        )
        .await?;

        let u_left = u_left_struct.payload;
        let w_left = w_left_struct.payload;

        let u_share = Replicated::new(u_left, self.u);
        let w_share = Replicated::new(w_left, self.w);

        // This should probably be done in parallel with the futures above
        let r = reveal(self.ctx.narrow(&Step::RevealR), record_5, self.r_share).await?;
        let t = u_share - (w_share * r);

        let is_valid = check_zero(self.ctx.narrow(&Step::CheckZero), record_6, t).await?;

        if is_valid {
            Ok(())
        } else {
            Err(Box::new(Error::MaliciousSecurityCheckFailed))
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::field::Fp31;
    use crate::protocol::{
        malicious::{SecurityValidator, Step},
        QueryId, RecordId,
    };
    use crate::test_fixture::{logging, make_contexts, make_world, share, TestWorld};
    use futures::future::{try_join, try_join_all};
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
            let mut v =
                SecurityValidator::new(ctx.narrow(&"SecurityValidatorInternal".to_string()));
            let r_share = v.r_share();

            let a_record_narrowed_context = ctx.narrow(&"record_1_hack".to_string());
            let b_record_narrowed_context = ctx.narrow(&"record_2_hack".to_string());

            let (ra, rb) = try_join(
                a_record_narrowed_context
                    .multiply(RecordId::from(0))
                    .await
                    .execute(a_shares[i], r_share),
                b_record_narrowed_context
                    .multiply(RecordId::from(1))
                    .await
                    .execute(b_shares[i], r_share),
            )
            .await?;

            v.accumulate_macs(
                a_record_narrowed_context.narrow(&Step::ValidateInput),
                RecordId::from(0),
                a_shares[i],
                ra,
            );
            v.accumulate_macs(
                b_record_narrowed_context.narrow(&Step::ValidateInput),
                RecordId::from(1),
                b_shares[i],
                rb,
            );

            let (ab, rab) = try_join(
                a_record_narrowed_context
                    .narrow(&"SingleMult".to_string())
                    .multiply(RecordId::from(0))
                    .await
                    .execute(a_shares[i], b_shares[i]),
                a_record_narrowed_context
                    .narrow(&"DoubleMult".to_string())
                    .multiply(RecordId::from(1))
                    .await
                    .execute(ra, b_shares[i]),
            )
            .await?;

            v.accumulate_macs(
                a_record_narrowed_context.narrow(&Step::ValidateMultiplySubstep),
                RecordId::from(0),
                ab,
                rab,
            );

            v.validate().await
        });

        try_join_all(futures).await?;

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
                    let mut v = SecurityValidator::new(
                        ctx.narrow(&"SecurityValidatorInternal".to_string()),
                    );
                    let r_share = v.r_share();

                    let mut inputs = Vec::with_capacity(100);
                    for i in 0..100 {
                        let step = format!("record_{}_hack", i);
                        let record_id = RecordId::from(i);
                        let record_narrowed_ctx = ctx.narrow(&step);

                        let x = input_shares[usize::try_from(i).unwrap()];
                        inputs.push((record_narrowed_ctx, record_id, x));
                    }

                    let rx_values = try_join_all(inputs.iter().map(
                        |(record_narrowed_ctx, record_id, x)| async move {
                            record_narrowed_ctx
                                .multiply(*record_id)
                                .await
                                .execute(*x, r_share)
                                .await
                        },
                    ))
                    .await?;

                    for i in 0..100 {
                        let (narrowed_ctx, record_id, x) = &inputs[i];
                        let rx = &rx_values[i];
                        v.accumulate_macs(
                            narrowed_ctx.narrow(&Step::ValidateInput),
                            *record_id,
                            *x,
                            *rx,
                        );
                    }

                    let mut mult_inputs = Vec::with_capacity(99);
                    for i in 0..99 {
                        let (narrowed_ctx, record_id, a) = &inputs[i];
                        let (_, _, b) = &inputs[i + 1];
                        let rb = &rx_values[i + 1];

                        mult_inputs.push((narrowed_ctx, *record_id, *a, *b, *rb));
                    }

                    #[allow(clippy::similar_names)]
                    let (ab_outputs, double_check_outputs) = try_join(
                        try_join_all(mult_inputs.iter().map(
                            |(narrowed_ctx, record_id, a, b, _)| async move {
                                narrowed_ctx
                                    .narrow(&"SingleMult".to_string())
                                    .multiply(*record_id)
                                    .await
                                    .execute(*a, *b)
                                    .await
                            },
                        )),
                        try_join_all(mult_inputs.iter().map(
                            |(narrowed_ctx, record_id, a, _, rb)| async move {
                                narrowed_ctx
                                    .narrow(&"DoubleMult".to_string())
                                    .multiply(*record_id)
                                    .await
                                    .execute(*a, *rb)
                                    .await
                            },
                        )),
                    )
                    .await?;

                    for i in 0..99 {
                        let ab = ab_outputs[i];
                        let rab = double_check_outputs[i];
                        let (narrowed_ctx, record_id, _, _, _) = &mult_inputs[i];
                        v.accumulate_macs(
                            narrowed_ctx.narrow(&Step::ValidateMultiplySubstep),
                            *record_id,
                            ab,
                            rab,
                        );
                    }

                    v.validate().await
                });

        try_join_all(futures).await?;

        Ok(())
    }
}
