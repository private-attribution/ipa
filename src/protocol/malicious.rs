use crate::{
    error::Error,
    ff::Field,
    helpers::Direction,
    protocol::{
        basics::{check_zero, Reveal},
        context::{Context, MaliciousContext, SemiHonestContext},
        prss::SharedRandomness,
        RecordId, RECORD_0, RECORD_1, RECORD_2,
    },
    secret_sharing::replicated::{
        malicious::{AdditiveShare as MaliciousReplicated, DowngradeMalicious},
        semi_honest::AdditiveShare as Replicated,
    },
    sync::{Arc, Mutex, Weak},
};
use futures::future::try_join;

/// Steps used by the validation component of malicious protocol execution.
/// In addition to these, an implicit step is used to initialize the value of `r`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Step {
    /// For upgrading all inputs from `Replicated` to `MaliciousReplicated`
    UpgradeInput,
    /// For the execution of the malicious protocol.
    MaliciousProtocol,
    /// The final validation steps.
    Validate,
}

impl crate::protocol::Substep for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::UpgradeInput => "upgrade_input",
            Self::MaliciousProtocol => "malicious_protocol",
            Self::Validate => "validate",
        }
    }
}

enum ValidateStep {
    /// Propagate the accumulated values of `u` and `w`.
    PropagateUW,
    /// Reveal the value of `r`, necessary for validation.
    RevealR,
    /// Check that there is no disagreement between accumulated values.
    CheckZero,
}

impl crate::protocol::Substep for ValidateStep {}

impl AsRef<str> for ValidateStep {
    fn as_ref(&self) -> &str {
        match self {
            Self::PropagateUW => "propagate_uw",
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
pub struct MaliciousValidatorAccumulator<F> {
    inner: Weak<Mutex<AccumulatorState<F>>>,
}

impl<F: Field> MaliciousValidatorAccumulator<F> {
    fn compute_dot_product_contribution(a: &Replicated<F>, b: &Replicated<F>) -> F {
        (a.left() + a.right()) * (b.left() + b.right()) - a.right() * b.right()
    }

    /// ## Panics
    /// Will panic if the mutex is poisoned
    pub fn accumulate_macs<I: SharedRandomness>(
        &self,
        prss: &I,
        record_id: RecordId,
        input: &MaliciousReplicated<F>,
    ) {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let random_constant = prss.generate_replicated(record_id);
        let u_contribution = Self::compute_dot_product_contribution(&random_constant, input.rx());
        let w_contribution = Self::compute_dot_product_contribution(
            &random_constant,
            input.x().access_without_downgrade(),
        );

        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut accumulator_state = arc_mutex.lock().unwrap();

        accumulator_state.u += u_contribution;
        accumulator_state.w += w_contribution;
        // LOCK END
    }
}

#[derive(Debug)]
pub struct MaliciousValidator<'a, F: Field> {
    r_share: Replicated<F>,
    u_and_w: Arc<Mutex<AccumulatorState<F>>>,
    protocol_ctx: MaliciousContext<'a, F>,
    validate_ctx: SemiHonestContext<'a, F>,
}

impl<'a, F: Field> MaliciousValidator<'a, F> {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(ctx: SemiHonestContext<'a, F>) -> MaliciousValidator<F> {
        // Use the current step in the context for initialization.
        let r_share = ctx.prss().generate_replicated(RECORD_0);
        let prss = ctx.prss();
        let state = AccumulatorState {
            u: prss.zero(RECORD_1),
            w: prss.zero(RECORD_2),
        };

        let u_and_w = Arc::new(Mutex::new(state));
        let accumulator = MaliciousValidatorAccumulator {
            inner: Arc::downgrade(&u_and_w),
        };
        let validate_ctx = ctx.narrow(&Step::Validate);
        let protocol_ctx = ctx.upgrade(
            &Step::MaliciousProtocol,
            &Step::UpgradeInput,
            accumulator,
            r_share.clone(),
        );
        MaliciousValidator {
            r_share,
            u_and_w,
            protocol_ctx,
            validate_ctx,
        }
    }

    pub fn r_share(&self) -> &Replicated<F> {
        &self.r_share
    }

    /// Get a copy of the context that can be used for malicious protocol execution.
    pub fn context<'b>(&'b self) -> MaliciousContext<'a, F> {
        self.protocol_ctx.clone()
    }

    /// ## Errors
    /// If the two information theoretic MACs are not equal (after multiplying by `r`), this indicates that one of the parties
    /// must have launched an additive attack. At this point the honest parties should abort the protocol. This method throws an
    /// error in such a case.
    /// TODO: add a "Drop Guard"
    ///
    /// ## Panics
    /// Will panic if the mutex is poisoned
    pub async fn validate<D: DowngradeMalicious>(self, values: D) -> Result<D::Target, Error> {
        // send our `u_i+1` value to the helper on the right
        let (u_share, w_share) = self.propagate_u_and_w().await?;

        // This should probably be done in parallel with the futures above
        let narrow_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::RevealR)
            .set_total_records(1);
        let r = narrow_ctx.reveal(RECORD_0, &self.r_share).await?;
        let t = u_share - &(w_share * r);

        let check_zero_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::CheckZero)
            .set_total_records(1);
        let is_valid = check_zero(check_zero_ctx, RECORD_0, &t).await?;

        if is_valid {
            // Yes, we're allowed to downgrade here.
            use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;
            Ok(values.downgrade().await.access_without_downgrade())
        } else {
            Err(Error::MaliciousSecurityCheckFailed)
        }
    }

    /// Turns out local values for `u` and `w` into proper replicated shares.
    async fn propagate_u_and_w(&self) -> Result<(Replicated<F>, Replicated<F>), Error> {
        let propagate_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::PropagateUW)
            .set_total_records(2);
        let channel = propagate_ctx.mesh();
        let helper_right = propagate_ctx.role().peer(Direction::Right);
        let helper_left = propagate_ctx.role().peer(Direction::Left);
        let (u_local, w_local) = {
            let state = self.u_and_w.lock().unwrap();
            (state.u, state.w)
        };
        try_join(
            channel.send(helper_right, RECORD_0, u_local),
            channel.send(helper_right, RECORD_1, w_local),
        )
        .await?;
        let (u_left, w_left): (F, F) = try_join(
            channel.receive(helper_left, RECORD_0),
            channel.receive(helper_left, RECORD_1),
        )
        .await?;
        let u_share = Replicated::new(u_left, u_local);
        let w_share = Replicated::new(w_left, w_local);
        Ok((u_share, w_share))
    }
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::iter::{repeat, zip};

    use crate::error::Error;
    use crate::ff::{Field, Fp31, Fp32BitPrime};
    use crate::helpers::Role;
    use crate::protocol::basics::SecureMul;
    use crate::protocol::context::Context;
    use crate::protocol::{malicious::MaliciousValidator, RecordId};
    use crate::rand::thread_rng;
    use crate::secret_sharing::{
        replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
        replicated::semi_honest::AdditiveShare as Replicated, IntoShares,
    };
    use crate::test_fixture::{join3v, Reconstruct, Runner, TestWorld};
    use futures::future::try_join_all;
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
        let world = TestWorld::new().await;
        let context = world.contexts::<Fp31>();
        let mut rng = thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let a_shares = a.share_with(&mut rng);
        let b_shares = b.share_with(&mut rng);

        let futures =
            zip(context, zip(a_shares, b_shares)).map(|(ctx, (a_share, b_share))| async move {
                let v = MaliciousValidator::new(ctx);
                let m_ctx = v.context();

                let (a_malicious, b_malicious) =
                    v.context().upgrade((a_share, b_share)).await.unwrap();

                let m_result = m_ctx
                    .set_total_records(1)
                    .multiply(RecordId::from(0), &a_malicious, &b_malicious)
                    .await?;

                // Save some cloned values so that we can check them.
                let r_share = v.r_share().clone();
                let result = v.validate(m_result.clone()).await?;
                assert_eq!(&result, m_result.x().access_without_downgrade());
                Ok::<_, Error>((m_result, r_share))
            });

        let [ab0, ab1, ab2] = join3v(futures).await;

        let ab = [
            ab0.0.x().access_without_downgrade(),
            ab1.0.x().access_without_downgrade(),
            ab2.0.x().access_without_downgrade(),
        ]
        .reconstruct();
        let rab = [ab0.0.rx(), ab1.0.rx(), ab2.0.rx()].reconstruct();
        let r = [&ab0.1, &ab1.1, &ab2.1].reconstruct();

        assert_eq!(ab, a * b);
        assert_eq!(rab, r * a * b);

        Ok(())
    }

    #[tokio::test]
    async fn upgrade_only() {
        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let a = rng.gen::<Fp32BitPrime>();

        let result = world
            .semi_honest(a, |ctx, a| async move {
                let v = MaliciousValidator::new(ctx);
                let m = v.context().upgrade(a).await.unwrap();
                v.validate(m).await.unwrap()
            })
            .await;
        assert_eq!(a, result.reconstruct());
    }

    #[tokio::test]
    async fn upgrade_only_tweaked() {
        let world = TestWorld::new().await;
        let mut rng = thread_rng();

        let a = rng.gen::<Fp32BitPrime>();

        for malicious_actor in Role::all() {
            world
                .semi_honest(a, |ctx, a| async move {
                    let a = if ctx.role() == *malicious_actor {
                        // This role is spoiling the value.
                        Replicated::new(a.left(), a.right() + Fp32BitPrime::ONE)
                    } else {
                        a
                    };
                    let v = MaliciousValidator::new(ctx);
                    let m = v.context().upgrade(a).await.unwrap();
                    match v.validate(m).await {
                        Ok(result) => panic!("Got a result {result:?}"),
                        Err(err) => assert!(matches!(err, Error::MaliciousSecurityCheckFailed)),
                    }
                })
                .await;
        }
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
        const COUNT: usize = 100;
        let world = TestWorld::new().await;
        let context = world.contexts::<Fp31>();
        let mut rng = thread_rng();

        let mut original_inputs = Vec::with_capacity(COUNT);
        for _ in 0..COUNT {
            let x = rng.gen::<Fp31>();
            original_inputs.push(x);
        }
        let shared_inputs: Vec<[Replicated<Fp31>; 3]> = original_inputs
            .iter()
            .map(|x| x.share_with(&mut rng))
            .collect();
        let h1_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[0].clone()).collect();
        let h2_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[1].clone()).collect();
        let h3_shares: Vec<Replicated<Fp31>> = shared_inputs.iter().map(|x| x[2].clone()).collect();

        let futures = context
            .into_iter()
            .zip([h1_shares, h2_shares, h3_shares])
            .map(|(ctx, input_shares)| async move {
                let v = MaliciousValidator::new(ctx);
                let m_ctx = v.context();

                let m_input = m_ctx.upgrade(input_shares).await.unwrap();

                let m_results = try_join_all(
                    zip(
                        repeat(m_ctx.set_total_records(COUNT - 1)).enumerate(),
                        zip(m_input.iter(), m_input.iter().skip(1)),
                    )
                    .map(|((i, ctx), (a_malicious, b_malicious))| async move {
                        ctx.multiply(RecordId::from(i), a_malicious, b_malicious)
                            .await
                    }),
                )
                .await?;

                let r_share = v.r_share().clone();
                let results = v.validate(m_results.clone()).await?;
                assert_eq!(
                    results.iter().collect::<Vec<_>>(),
                    m_results
                        .iter()
                        .map(|x| x.x().access_without_downgrade())
                        .collect::<Vec<_>>()
                );
                Ok::<_, Error>((m_results, r_share))
            });

        let processed_outputs = join3v(futures).await;

        let r = [
            &processed_outputs[0].1,
            &processed_outputs[1].1,
            &processed_outputs[2].1,
        ]
        .reconstruct();

        for i in 0..99 {
            let x1 = original_inputs[i];
            let x2 = original_inputs[i + 1];
            let x1_times_x2 = [
                processed_outputs[0].0[i].x().access_without_downgrade(),
                processed_outputs[1].0[i].x().access_without_downgrade(),
                processed_outputs[2].0[i].x().access_without_downgrade(),
            ]
            .reconstruct();
            let r_times_x1_times_x2 = [
                processed_outputs[0].0[i].rx(),
                processed_outputs[1].0[i].rx(),
                processed_outputs[2].0[i].rx(),
            ]
            .reconstruct();

            assert_eq!(x1 * x2, x1_times_x2);
            assert_eq!(r * x1 * x2, r_times_x1_times_x2);
        }

        Ok(())
    }
}
