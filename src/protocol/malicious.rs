use crate::{
    error::{BoxError, Error},
    ff::Field,
    helpers::{fabric::Network, Direction},
    protocol::{
        check_zero::check_zero, context::ProtocolContext, prss::IndexedSharedRandomness,
        reveal::reveal, RecordId, RECORD_0, RECORD_1, RECORD_2, RECORD_3,
    },
    secret_sharing::{MaliciousReplicated, Replicated},
};
use futures::future::try_join;
use std::sync::{Arc, Mutex, Weak};

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

/// This code is an implementation of the approach found in the paper:
/// "Fast Large-Scale Honest-Majority MPC for Malicious Adversaries"
/// by K. Chida, D. Genkin, K. Hamada, D. Ikarashi, R. Kikuchi, Y. Lindell, and A. Nof
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// As the paragraph labeled "Reducing Memory" on page 25 explains very well, it's more efficient
/// to utilize protocol 5.3 as compared to Protocol 4.1.
/// As that paragraph explains:
/// "...the parties can locally store the partial sums for `u_i` and `w_i`,
/// and all previous shares that are no longer needed for the circuit evaluation can be discarded."
///
/// For this reason, this implementation follows Protocol 5.3: "Computing Arithmetic Circuits Over Any Finite F"
///
/// The summary of the protocol is as follows:
/// 1.) The parties utilize shared randomness to generate (without interaction) a secret-sharing of an unknown value `r`
/// 2.) The parties multiply their secret-sharings of each input to the arithmetic circuit by `r` to obtain a "mirror" of each input share
/// 3.) For all local operations (i.e. addition, subtraction, negation, multiplication by a constant), the parties locally perform those
/// operations on both the sharing of the original value, and the sharing of the original value times r
/// 4.) Each time that there is a protocol involving communication between the helpers, which is secure **up to an additive attack**,
/// the parties perform the protocol in duplicate, once to obtain the originally intended output and once to obtain that output times `r`.
/// For example, instead of just multiplying `a` and `b`, the parties now hold sharings of (`a`, `r*a`) and (`b`, `r*b`).
/// They perform two multiplication protocols to obtain sharings of both (`a*b`, `r*a*b`).
/// 5.) For each input, and for each multiplication or reshare, (basically any time one of the parties had an opportunity to launch an additive attack)
/// we update two information-theoretic MACs. Each MAC is a dot-product.
/// `[u] = Σ[α_k][r*z_k]`
/// `[w] = Σ[αk][zk]`
/// where `z_k` represents every original input, or output of a multiplication,
/// and where `r*z_k` is just the mirror value (the original times `r`) that is being computed along the way through the circuit.
/// The `α_k` are randomly secret-shared values which the parties can generate without interaction using PRSS.
/// Clearly, the only difference between `[u]` and `[w]` is a factor of `r`.
/// 6.) Once the arithmetic circuit is complete, the parties can reveal the randomly chosen value `r`.
/// 7.) Now the parties can each locally compute `[T] = [u] - r*[w]`
/// 8.) Finally, the parties can run the `CheckZero` protocol to confirm that `[T]` is a sharing of zero.
/// If it is NOT, this indicates that one of the parties must have at some point launched an additive attack, and the parties should abort the protocol.
///
/// The really nice thing, is that computing the dot-product of two secret shared vectors can be done at the cost of just one multiplication.
/// This means that we can locally accumulate values along the way, and only perform a tiny amount of communication when the arithmetic circuit is complete
/// and the parties wish to validate the circuit. This makes for a very memory efficient implementation.
///
#[derive(Clone, Copy, Debug)]
struct AccumulatorState<F> {
    u: F,
    w: F,
}

#[derive(Clone, Debug)]
pub struct SecurityValidatorAccumulator<F> {
    inner: Weak<Mutex<AccumulatorState<F>>>,
}

impl<F: Field> SecurityValidatorAccumulator<F> {
    fn compute_dot_product_contribution(a: Replicated<F>, b: Replicated<F>) -> F {
        (a.left() + a.right()) * (b.left() + b.right()) - a.right() * b.right()
    }

    /// ## Panics
    /// Will panic if the mutex is poisoned
    pub fn accumulate_macs(
        &self,
        prss: &Arc<IndexedSharedRandomness>,
        record_id: RecordId,
        input: MaliciousReplicated<F>,
    ) {
        let random_constant = prss.generate_replicated(record_id);

        let u_contribution = Self::compute_dot_product_contribution(random_constant, input.rx());
        let w_contribution = Self::compute_dot_product_contribution(random_constant, input.x());

        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut accumulator_state = arc_mutex.lock().unwrap();

        accumulator_state.u += u_contribution;
        accumulator_state.w += w_contribution;
        // LOCK END
    }
}

#[allow(dead_code)]
pub struct SecurityValidator<F> {
    r_share: Replicated<F>,
    u_and_w: Arc<Mutex<AccumulatorState<F>>>,
}

impl<F: Field> SecurityValidator<F> {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new<N: Network>(ctx: ProtocolContext<'_, N, F>) -> SecurityValidator<F> {
        let prss = ctx.prss();

        let r_share = prss.generate_replicated(RECORD_0);

        let state = AccumulatorState {
            u: prss.zero(RECORD_1),
            w: prss.zero(RECORD_2),
        };

        SecurityValidator {
            r_share,
            u_and_w: Arc::new(Mutex::new(state)),
        }
    }

    pub fn accumulator(&self) -> SecurityValidatorAccumulator<F> {
        SecurityValidatorAccumulator {
            inner: Arc::downgrade(&self.u_and_w),
        }
    }

    pub fn r_share(&self) -> Replicated<F> {
        self.r_share
    }

    /// ## Errors
    /// If the two information theoretic MACs are not equal (after multiplying by `r`), this indicates that one of the parties
    /// must have launched an additive attack. At this point the honest parties should abort the protocol. This method throws an
    /// error in such a case.
    /// TODO: add a "Drop Guard"
    ///
    /// ## Panics
    /// Will panic if the mutex is poisoned
    #[allow(clippy::await_holding_lock)]
    pub async fn validate<N: Network>(
        self,
        ctx: ProtocolContext<'_, N, F>,
    ) -> Result<(), BoxError> {
        // send our `u_i+1` value to the helper on the right
        let channel = ctx.mesh();
        let helper_right = ctx.role().peer(Direction::Right);
        let helper_left = ctx.role().peer(Direction::Left);

        let state = self.u_and_w.lock().unwrap();
        try_join(
            channel.send(helper_right, RECORD_0, state.u),
            channel.send(helper_right, RECORD_1, state.w),
        )
        .await?;

        // receive `u_i` value from helper to the left
        let (u_left, w_left): (F, F) = try_join(
            channel.receive(helper_left, RECORD_0),
            channel.receive(helper_left, RECORD_1),
        )
        .await?;

        let u_share = Replicated::new(u_left, state.u);
        let w_share = Replicated::new(w_left, state.w);

        // This should probably be done in parallel with the futures above
        let r = reveal(ctx.narrow(&Step::RevealR), RECORD_2, self.r_share).await?;
        let t = u_share - (w_share * r);

        let is_valid = check_zero(ctx.narrow(&Step::CheckZero), RECORD_3, t).await?;

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
    use crate::ff::Fp31;
    use crate::protocol::{
        malicious::{SecurityValidator, Step},
        QueryId, RecordId,
    };
    use crate::secret_sharing::{MaliciousReplicated, Replicated};
    use crate::test_fixture::{logging, make_contexts, make_world, share, TestWorld};
    use futures::future::{try_join, try_join_all};
    use proptest::prelude::Rng;

    /// This is the simplest arithmetic circuit that allows us to test all of the pieces of this validator
    /// A -
    ///     \
    ///      Mult_Gate -> A*B
    ///     /
    /// B -
    ///
    /// This circuit has two inputs, A and B. These two inputs are multiplied together. That's it.
    ///
    /// To achieve malicious security, the entire circuit must be run twice, once with the original inputs,
    /// and once with all the inputs times a random, secret-shared value `r`. Two information theoretic MACs
    /// are updated; once for each input, and once for each multiplication. At the end of the circuit, these
    /// MACs are compared. If any helper deviated from the protocol, chances are that the MACs will not match up.
    /// There is a small chance of failure which is `2 / |F|`, where `|F|` is the cardinality of the prime field.
    #[tokio::test]
    async fn simplest_circuit() -> Result<(), BoxError> {
        logging::setup();

        let world: TestWorld = make_world(QueryId);
        let context = make_contexts(&world);
        let mut rng = rand::thread_rng();

        let a = Fp31::from(rng.gen::<u128>());
        let b = Fp31::from(rng.gen::<u128>());

        let a_shares = share(a, &mut rng);
        let b_shares = share(b, &mut rng);

        let futures = (0..3).into_iter().zip(context).map(|(i, ctx)| async move {
            let v = SecurityValidator::new(ctx.narrow("SecurityValidatorInit"));
            let acc = v.accumulator();
            let r_share = v.r_share();

            let a_ctx = ctx.narrow("1");
            let b_ctx = ctx.narrow("2");

            let (ra, rb) = try_join(
                a_ctx
                    .narrow("input")
                    .multiply(RecordId::from(0))
                    .await
                    .execute(a_shares[i], r_share),
                b_ctx
                    .narrow("input")
                    .multiply(RecordId::from(1))
                    .await
                    .execute(b_shares[i], r_share),
            )
            .await?;

            let a_malicious = MaliciousReplicated::new(a_shares[i], ra);
            let b_malicious = MaliciousReplicated::new(b_shares[i], rb);

            acc.accumulate_macs(
                &a_ctx.narrow(&Step::ValidateInput).prss(),
                RecordId::from(0),
                a_malicious,
            );
            acc.accumulate_macs(
                &b_ctx.narrow(&Step::ValidateInput).prss(),
                RecordId::from(1),
                b_malicious,
            );

            let (ab, rab) = try_join(
                a_ctx
                    .narrow("SingleMult")
                    .multiply(RecordId::from(0))
                    .await
                    .execute(a_shares[i], b_shares[i]),
                a_ctx
                    .narrow("DoubleMult")
                    .multiply(RecordId::from(1))
                    .await
                    .execute(ra, b_shares[i]),
            )
            .await?;

            acc.accumulate_macs(
                &a_ctx.narrow(&Step::ValidateMultiplySubstep).prss(),
                RecordId::from(0),
                MaliciousReplicated::new(ab, rab),
            );

            v.validate(ctx.narrow("SecurityValidatorValidate")).await
        });

        try_join_all(futures).await?;

        Ok(())
    }

    /// This is a big more complex arithmetic circuit that tests the validator a bit more thoroughly
    /// input1   -
    ///              input1 * input2
    /// input2   -
    ///              input2 * input3
    /// input3   -
    /// ...
    /// input98  -
    ///              input98 * input99
    /// input99  -
    ///              input99 * input100
    /// input100 -
    ///
    /// This circuit has 100 inputs. Each input is multiplied with the adjacent inputs to produce 99 outputs.
    ///
    /// To achieve malicious security, the entire circuit must be run twice, once with the original inputs,
    /// and once with all the inputs times a random, secret-shared value `r`. Two information theoretic MACs
    /// are updated; once for each input, and once for each multiplication. At the end of the circuit, these
    /// MACs are compared. If any helper deviated from the protocol, chances are that the MACs will not match up.
    /// There is a small chance of failure which is `2 / |F|`, where `|F|` is the cardinality of the prime field.
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
                    let v = SecurityValidator::new(ctx.narrow("SecurityValidatorInit"));
                    let acc = v.accumulator();

                    let mut row_narrowed_contexts = Vec::with_capacity(100);
                    for i in 0..100 {
                        row_narrowed_contexts.push(ctx.narrow(&format!("row {}", i)));
                    }

                    let r_share = v.r_share();

                    let rx_values: Vec<Replicated<Fp31>> = try_join_all(
                        input_shares
                            .iter()
                            .zip(row_narrowed_contexts.iter())
                            .enumerate()
                            .map(|(i, (x, ctx))| async move {
                                ctx.narrow("mult")
                                    .multiply(RecordId::from(u32::try_from(i).unwrap()))
                                    .await
                                    .execute(*x, r_share)
                                    .await
                            }),
                    )
                    .await?;

                    let _ = input_shares.iter().zip(rx_values.iter()).enumerate().map(
                        |(i, (x, rx))| {
                            acc.accumulate_macs(
                                &ctx.narrow(&Step::ValidateInput).prss(),
                                RecordId::from(u32::try_from(i).unwrap()),
                                MaliciousReplicated::new(*x, *rx),
                            );
                        },
                    );

                    let (ab_outputs, double_check_outputs) = try_join(
                        try_join_all(
                            input_shares
                                .iter()
                                .zip(input_shares.iter().skip(1))
                                .zip(row_narrowed_contexts.iter())
                                .enumerate()
                                .map(|(i, ((a, b), ctx))| async move {
                                    ctx.narrow("SingleMult")
                                        .multiply(RecordId::from(u32::try_from(i).unwrap()))
                                        .await
                                        .execute(*a, *b)
                                        .await
                                }),
                        ),
                        try_join_all(
                            input_shares
                                .iter()
                                .zip(rx_values.iter().skip(1))
                                .zip(row_narrowed_contexts.iter())
                                .enumerate()
                                .map(|(i, ((a, rb), ctx))| async move {
                                    ctx.narrow("DoubleMult")
                                        .multiply(RecordId::from(u32::try_from(i).unwrap()))
                                        .await
                                        .execute(*a, *rb)
                                        .await
                                }),
                        ),
                    )
                    .await?;

                    let _ = ab_outputs
                        .iter()
                        .zip(double_check_outputs.iter())
                        .enumerate()
                        .map(|(i, (ab, rab))| {
                            acc.accumulate_macs(
                                &ctx.narrow(&Step::ValidateMultiplySubstep).prss(),
                                RecordId::from(u32::try_from(i).unwrap()),
                                MaliciousReplicated::new(*ab, *rab),
                            );
                        });

                    v.validate(ctx.narrow("SecurityValidatorValidate")).await
                });

        try_join_all(futures).await?;

        Ok(())
    }
}
