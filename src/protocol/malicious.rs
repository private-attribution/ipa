use crate::protocol::context::SemiHonestContext;
use crate::protocol::reveal::Reveal;
use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        check_zero::check_zero, context::Context, prss::IndexedSharedRandomness, RecordId,
        RECORD_0, RECORD_1, RECORD_2,
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

impl crate::protocol::Substep for Step {}

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
    fn compute_dot_product_contribution(a: &Replicated<F>, b: &Replicated<F>) -> F {
        (a.left() + a.right()) * (b.left() + b.right()) - a.right() * b.right()
    }

    /// ## Panics
    /// Will panic if the mutex is poisoned
    pub fn accumulate_macs(
        &self,
        prss: &Arc<IndexedSharedRandomness>,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
    ) {
        let random_constant = prss.generate_replicated(record_id);

        let u_contribution = Self::compute_dot_product_contribution(&random_constant, input.rx());
        let w_contribution = Self::compute_dot_product_contribution(&random_constant, input.x());

        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut accumulator_state = arc_mutex.lock().unwrap();

        accumulator_state.u += u_contribution;
        accumulator_state.w += w_contribution;
        // LOCK END
    }
}

#[allow(dead_code)]
pub struct SecurityValidator<F: Field> {
    r_share: Replicated<F>,
    u_and_w: Arc<Mutex<AccumulatorState<F>>>,
}

impl<F: Field> SecurityValidator<F> {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(ctx: SemiHonestContext<'_, F>) -> SecurityValidator<F> {
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

    pub fn r_share(&self) -> &Replicated<F> {
        &self.r_share
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
    pub async fn validate(self, ctx: SemiHonestContext<'_, F>) -> Result<(), Error> {
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
        let r = ctx
            .narrow(&Step::RevealR)
            .reveal(RECORD_0, &self.r_share)
            .await?;
        let t = u_share - &(w_share * r);

        let is_valid = check_zero(ctx.narrow(&Step::CheckZero), RECORD_0, &t).await?;

        if is_valid {
            Ok(())
        } else {
            Err(Error::MaliciousSecurityCheckFailed)
        }
    }
}

#[cfg(test)]
pub mod tests {
    use std::iter::zip;

    use crate::error::Error;
    use crate::ff::Fp31;
    use crate::protocol::context::Context;
    use crate::protocol::mul::SecureMul;
    use crate::protocol::{
        malicious::{SecurityValidator, Step},
        QueryId, RecordId,
    };
    use crate::secret_sharing::{MaliciousReplicated, Replicated};
    use crate::test_fixture::{
        make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
    };
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
    async fn simplest_circuit() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let a_shares = share(a, &mut rng);
        let b_shares = share(b, &mut rng);

        let futures =
            zip(context, zip(a_shares, b_shares)).map(|(ctx, (a_share, b_share))| async move {
                let v = SecurityValidator::new(ctx.narrow("SecurityValidatorInit"));
                let acc = v.accumulator();
                let r_share = v.r_share();

                let a_ctx = ctx.narrow("1");
                let b_ctx = ctx.narrow("2");

                let (ra, rb) = try_join(
                    a_ctx
                        .narrow("input")
                        .multiply(RecordId::from(0), &a_share, r_share),
                    b_ctx
                        .narrow("input")
                        .multiply(RecordId::from(0), &b_share, r_share),
                )
                .await?;

                let a_ctx = a_ctx.upgrade_to_malicious(acc.clone(), r_share.clone());
                let b_ctx = b_ctx.upgrade_to_malicious(acc.clone(), r_share.clone());

                let a_malicious = MaliciousReplicated::new(a_share, ra);
                let b_malicious = MaliciousReplicated::new(b_share, rb);

                acc.accumulate_macs(
                    &a_ctx.narrow(&Step::ValidateInput).prss(),
                    RecordId::from(0),
                    &a_malicious,
                );
                acc.accumulate_macs(
                    &b_ctx.narrow(&Step::ValidateInput).prss(),
                    RecordId::from(0),
                    &b_malicious,
                );

                let mult_result = a_ctx
                    .multiply(RecordId::from(0), &a_malicious, &b_malicious)
                    .await?;

                let r_share = v.r_share().clone();
                v.validate(ctx.narrow("SecurityValidatorValidate")).await?;
                Ok::<_, Error>((mult_result, r_share))
            });

        let [ab0, ab1, ab2] = <[_; 3]>::try_from(try_join_all(futures).await?).unwrap();

        let ab = validate_and_reconstruct(ab0.0.x(), ab1.0.x(), ab2.0.x());
        let rab = validate_and_reconstruct(ab0.0.rx(), ab1.0.rx(), ab2.0.rx());
        let r = validate_and_reconstruct(&ab0.1, &ab1.1, &ab2.1);

        assert_eq!(ab, a * b);
        assert_eq!(rab, r * a * b);

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
    async fn complex_circuit() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let context = make_contexts::<Fp31>(&world);
        let mut rng = rand::thread_rng();

        let mut original_inputs = Vec::with_capacity(100);
        for _ in 0..100 {
            let x = rng.gen::<Fp31>();
            original_inputs.push(x);
        }
        let shared_inputs: Vec<[Replicated<Fp31>; 3]> = original_inputs
            .iter()
            .map(|x| share(*x, &mut rng))
            .collect();
        let h1_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[0].clone()).collect();
        let h2_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[1].clone()).collect();
        let h3_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[2].clone()).collect();

        let futures = context
            .into_iter()
            .zip(vec![h1_shares, h2_shares, h3_shares])
            .map(|(ctx, input_shares)| async move {
                let v = SecurityValidator::new(ctx.narrow("SecurityValidatorInit"));
                let acc = v.accumulator();

                let mut row_narrowed_contexts = Vec::with_capacity(100);
                for i in 0..100 {
                    row_narrowed_contexts.push(ctx.narrow(&format!("row {}", i)));
                }

                let r_share = v.r_share();

                let maliciously_secure_inputs =
                    try_join_all(input_shares.iter().zip(row_narrowed_contexts.iter()).map(
                        |(x, ctx)| async move {
                            let rx = ctx
                                .narrow("mult")
                                .multiply(RecordId::from(0), x, r_share)
                                .await?;

                            Ok::<_, Error>(MaliciousReplicated::new(x.clone(), rx))
                        },
                    ))
                    .await?;

                let _ = maliciously_secure_inputs
                    .iter()
                    .zip(row_narrowed_contexts.iter())
                    .map(|(maliciously_secure_input, ctx)| {
                        acc.accumulate_macs(
                            &ctx.narrow(&Step::ValidateInput).prss(),
                            RecordId::from(0),
                            maliciously_secure_input,
                        );
                    });

                let mult_results = try_join_all(
                    maliciously_secure_inputs
                        .iter()
                        .zip(maliciously_secure_inputs.iter().skip(1))
                        .zip(row_narrowed_contexts.iter())
                        .map(|((a_malicious, b_malicious), ctx)| {
                            let acc = acc.clone();
                            async move {
                                ctx.narrow("Circuit_Step_2")
                                    .upgrade_to_malicious(acc, r_share.clone())
                                    .multiply(RecordId::from(0), a_malicious, b_malicious)
                                    .await
                            }
                        }),
                )
                .await?;

                let r_share = v.r_share().clone();
                v.validate(ctx.narrow("SecurityValidatorValidate")).await?;
                Ok::<_, Error>((mult_results, r_share))
            });

        let processed_outputs = try_join_all(futures).await?;

        let r = validate_and_reconstruct(
            &processed_outputs[0].1,
            &processed_outputs[1].1,
            &processed_outputs[2].1,
        );

        for i in 0..99 {
            let x1 = original_inputs[i];
            let x2 = original_inputs[i + 1];
            let x1_times_x2 = validate_and_reconstruct(
                processed_outputs[0].0[i].x(),
                processed_outputs[1].0[i].x(),
                processed_outputs[2].0[i].x(),
            );
            let r_times_x1_times_x2 = validate_and_reconstruct(
                processed_outputs[0].0[i].rx(),
                processed_outputs[1].0[i].rx(),
                processed_outputs[2].0[i].rx(),
            );

            assert_eq!(x1 * x2, x1_times_x2);
            assert_eq!(r * x1 * x2, r_times_x1_times_x2);
        }

        Ok(())
    }
}
