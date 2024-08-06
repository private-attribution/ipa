use std::{
    any::type_name,
    fmt::{Debug, Formatter},
    marker::PhantomData,
};

use async_trait::async_trait;
use typenum::Const;

use crate::{
    error::Error,
    ff::Field,
    helpers::{Direction, TotalRecords},
    protocol::{
        basics::{check_zero::malicious_check_zero, malicious_reveal},
        context::{
            step::{MaliciousProtocolStep as Step, ValidateStep},
            Base, Context, MaliciousContext, UpgradedContext, UpgradedMaliciousContext,
            UpgradedSemiHonestContext,
        },
        prss::{FromPrss, SharedRandomness},
        RecordId,
    },
    secret_sharing::{
        replicated::{
            malicious::{
                AdditiveShare as MaliciousReplicated, DowngradeMalicious, ExtendableField,
                ExtendableFieldSimd,
            },
            semi_honest::AdditiveShare as Replicated,
            ReplicatedSecretSharing,
        },
        FieldSimd, SharedValue,
    },
    sharding::ShardBinding,
    sync::{Arc, Mutex, Weak},
};

#[async_trait]
pub trait Validator<F: ExtendableField> {
    type Context: UpgradedContext;

    fn context(&self) -> Self::Context;
    async fn validate<D: DowngradeMalicious>(self, values: D) -> Result<D::Target, Error>;
}

pub struct SemiHonest<'a, B: ShardBinding, F: ExtendableField> {
    context: UpgradedSemiHonestContext<'a, B, F>,
    _f: PhantomData<F>,
}

impl<'a, B: ShardBinding, F: ExtendableField> SemiHonest<'a, B, F> {
    pub(super) fn new(inner: Base<'a, B>) -> Self {
        Self {
            context: UpgradedSemiHonestContext::new(inner),
            _f: PhantomData,
        }
    }
}

#[async_trait]
impl<'a, B: ShardBinding, F: ExtendableField> Validator<F> for SemiHonest<'a, B, F> {
    type Context = UpgradedSemiHonestContext<'a, B, F>;

    fn context(&self) -> Self::Context {
        self.context.clone()
    }

    async fn validate<D: DowngradeMalicious>(self, values: D) -> Result<D::Target, Error> {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;
        Ok(values.downgrade().await.access_without_downgrade())
    }
}

impl<B: ShardBinding, F: ExtendableField> Debug for SemiHonest<'_, B, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SemiHonestValidator<{:?}, {:?}>",
            type_name::<B>(),
            type_name::<F>()
        )
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
struct AccumulatorState<T: Field> {
    u: T,
    w: T,
}

impl<T: Field> AccumulatorState<T> {
    pub fn new(u: T, w: T) -> Self {
        Self { u, w }
    }
}

#[derive(Clone, Debug)]
pub struct MaliciousAccumulator<F: ExtendableField> {
    inner: Weak<Mutex<AccumulatorState<F::ExtendedField>>>,
}

impl<F: ExtendableField> MaliciousAccumulator<F> {
    fn compute_dot_product_contribution<const N: usize>(
        a: &Replicated<F::ExtendedField, N>,
        b: &Replicated<F::ExtendedField, N>,
    ) -> F::ExtendedField
    where
        F::ExtendedField: FieldSimd<N>,
    {
        // TODO: clones exist here to satisfy trait bounds (Add(A, &A)) and we still can't express
        // bounds on &Self references properly. See `RefOps` trait for details
        let vectorized_share = (a.left_arr().clone() + a.right_arr())
            * &(b.left_arr().clone() + b.right_arr())
            - a.right_arr().clone() * b.right_arr();
        vectorized_share
            .into_iter()
            .fold(F::ExtendedField::ZERO, |acc, x| acc + x)
    }

    /// ## Panics
    /// Will panic if the mutex is poisoned
    pub fn accumulate_macs<I: SharedRandomness, const N: usize>(
        &self,
        prss: &I,
        record_id: RecordId,
        input: &MaliciousReplicated<F, N>,
    ) where
        F: ExtendableFieldSimd<N>,
        Replicated<F::ExtendedField, N>: FromPrss,
    {
        use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;

        let x = input.x().access_without_downgrade();

        //
        // This code is an optimization to our malicious compiler that is drawn from:
        // "Field Extension in Secret-Shared Form and Its Applications to Efficient Secure Computation"
        // R. Kikuchi, N. Attrapadung, K. Hamada, D. Ikarashi, A. Ishida, T. Matsuda, Y. Sakai, and J. C. N. Schuldt
        // <https://eprint.iacr.org/2019/386.pdf>
        //
        // See protocol 4.15
        // In step 5: Verification Stage, it says:
        //
        // The parties locally compute the induced share `[[z_k]] = f([z_k], 0, . . . , 0)`
        // of the output wire of the k-th multiplication gate.
        // Then, the parties call `Ḟ_product` on vectors
        // `([[ᾶ_1]], . . . , [[ᾶ_N ]], [[β_1]], . . . , [[β_M]])` and `([[z_1]], . . . , [[z_N]], [[v_1]], . . . , [[v_M]])` to receive `[[ŵ]]`
        let induced_share = x.induced();
        let random_constant = prss.generate(record_id);
        let u_contribution = Self::compute_dot_product_contribution(&random_constant, input.rx());
        let w_contribution =
            Self::compute_dot_product_contribution(&random_constant, &induced_share);

        let arc_mutex = self.inner.upgrade().unwrap();
        // LOCK BEGIN
        let mut accumulator_state = arc_mutex.lock().unwrap();

        accumulator_state.u += u_contribution;
        accumulator_state.w += w_contribution;
        // LOCK END
    }
}

pub struct Malicious<'a, F: ExtendableField> {
    r_share: Replicated<F::ExtendedField>,
    u_and_w: Arc<Mutex<AccumulatorState<F::ExtendedField>>>,
    protocol_ctx: UpgradedMaliciousContext<'a, F>,
    validate_ctx: Base<'a>,
}

#[async_trait]
impl<'a, F> Validator<F> for Malicious<'a, F>
where
    F: ExtendableField,
{
    type Context = UpgradedMaliciousContext<'a, F>;

    /// Get a copy of the context that can be used for malicious protocol execution.
    fn context(&self) -> Self::Context {
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
    #[tracing::instrument(name = "validate", skip_all, fields(gate = %self.validate_ctx.gate().as_ref()))]
    async fn validate<D: DowngradeMalicious>(self, values: D) -> Result<D::Target, Error> {
        // send our `u_i+1` value to the helper on the right
        let (u_share, w_share) = self.propagate_u_and_w().await?;

        // This should probably be done in parallel with the futures above
        let narrow_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::RevealR)
            .set_total_records(TotalRecords::ONE);
        let r = <F as ExtendableField>::ExtendedField::from_array(
            &malicious_reveal(narrow_ctx, RecordId::FIRST, None, &self.r_share)
                .await?
                .expect("full reveal should always return a value"),
        );
        let t = u_share - &(w_share * r);

        let check_zero_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::CheckZero)
            .set_total_records(TotalRecords::ONE);
        let is_valid = malicious_check_zero(check_zero_ctx, RecordId::FIRST, &t).await?;

        if is_valid {
            // Yes, we're allowed to downgrade here.
            use crate::secret_sharing::replicated::malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious;
            Ok(values.downgrade().await.access_without_downgrade())
        } else {
            Err(Error::MaliciousSecurityCheckFailed)
        }
    }
}

impl<'a, F: ExtendableField> Malicious<'a, F> {
    #[must_use]
    #[allow(clippy::needless_pass_by_value)]
    pub fn new(ctx: MaliciousContext<'a>) -> Self {
        // Use the current step in the context for initialization.
        let r_share: Replicated<F::ExtendedField> = ctx.prss().generate(RecordId::FIRST);
        let prss = ctx.prss();
        let u: F::ExtendedField = prss.zero(RecordId::FIRST + 1);
        let w: F::ExtendedField = prss.zero(RecordId::FIRST + 2);
        let state = AccumulatorState::new(u, w);

        let u_and_w = Arc::new(Mutex::new(state));
        let accumulator = MaliciousAccumulator::<F> {
            inner: Arc::downgrade(&u_and_w),
        };
        let validate_ctx = ctx.narrow(&Step::Validate).validator_context();
        let protocol_ctx = ctx.upgrade(&Step::MaliciousProtocol, accumulator, r_share.clone());
        Self {
            r_share,
            u_and_w,
            protocol_ctx,
            validate_ctx,
        }
    }

    pub fn r_share(&self) -> &Replicated<F::ExtendedField> {
        &self.r_share
    }

    /// Turns out local values for `u` and `w` into proper replicated shares.
    async fn propagate_u_and_w(
        &self,
    ) -> Result<(Replicated<F::ExtendedField>, Replicated<F::ExtendedField>), Error> {
        use futures::future::try_join;

        let propagate_ctx = self
            .validate_ctx
            .narrow(&ValidateStep::PropagateUAndW)
            .set_total_records(Const::<2>);
        let helper_right = propagate_ctx.send_channel(propagate_ctx.role().peer(Direction::Right));
        let helper_left = propagate_ctx.recv_channel(propagate_ctx.role().peer(Direction::Left));
        let (u_local, w_local) = {
            let state = self.u_and_w.lock().unwrap();
            (state.u, state.w)
        };
        try_join(
            helper_right.send(RecordId::FIRST, u_local),
            helper_right.send(RecordId::FIRST + 1, w_local),
        )
        .await?;
        let (u_left, w_left): (F::ExtendedField, F::ExtendedField) = try_join(
            helper_left.receive(RecordId::FIRST),
            helper_left.receive(RecordId::FIRST + 1),
        )
        .await?;
        let u_share = Replicated::new(u_left, u_local);
        let w_share = Replicated::new(w_left, w_local);
        Ok((u_share, w_share))
    }
}

impl<F: ExtendableField> Debug for Malicious<'_, F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "MaliciousValidator<{:?}>", type_name::<F>())
    }
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::iter::{repeat, zip};

    use crate::{
        error::Error,
        ff::{Field, Fp31, Fp32BitPrime},
        helpers::Role,
        protocol::{
            basics::SecureMul,
            context::{upgrade::Upgradable, validator::Validator, Context, UpgradableContext},
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{
            replicated::{
                malicious::ThisCodeIsAuthorizedToDowngradeFromMalicious,
                semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
            },
            IntoShares,
        },
        seq_join::SeqJoin,
        test_fixture::{join3v, Reconstruct, Runner, TestWorld},
    };

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
        let world = TestWorld::default();
        let context = world.malicious_contexts();
        let mut rng = thread_rng();

        let a = rng.gen::<Fp31>();
        let b = rng.gen::<Fp31>();

        let a_shares = a.share_with(&mut rng);
        let b_shares = b.share_with(&mut rng);

        let futures =
            zip(context, zip(a_shares, b_shares)).map(|(ctx, (a_share, b_share))| async move {
                let v = ctx.validator();
                let m_ctx = v.context();

                let (a_malicious, b_malicious) = (a_share, b_share)
                    .upgrade(RecordId::FIRST, m_ctx.set_total_records(1))
                    .await
                    .unwrap();

                let m_result = a_malicious
                    .multiply(&b_malicious, m_ctx.set_total_records(1), RecordId::from(0))
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
        let world = TestWorld::default();
        let mut rng = thread_rng();

        let a = rng.gen::<Fp32BitPrime>();

        let result = world
            .malicious(a, |ctx, a| async move {
                let v = ctx.validator();
                let m = a
                    .upgrade(RecordId::FIRST, v.context().set_total_records(1))
                    .await
                    .unwrap();
                v.validate(m).await.unwrap()
            })
            .await;
        assert_eq!(a, result.reconstruct());
    }

    #[tokio::test]
    async fn upgrade_only_tweaked() {
        let world = TestWorld::default();
        let mut rng = thread_rng();

        let a = rng.gen::<Fp32BitPrime>();

        for malicious_actor in Role::all() {
            world
                .malicious(a, |ctx, a| async move {
                    let a = if ctx.role() == *malicious_actor {
                        // This role is spoiling the value.
                        Replicated::new(a.left(), a.right() + Fp32BitPrime::ONE)
                    } else {
                        a
                    };
                    let v = ctx.validator();
                    let m = a
                        .upgrade(RecordId::FIRST, v.context().set_total_records(1))
                        .await
                        .unwrap();
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
        let world = TestWorld::default();
        let context = world.malicious_contexts();
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
                let v = ctx.validator();
                let m_ctx = v.context();

                let m_input = input_shares
                    .upgrade(RecordId::FIRST, m_ctx.set_total_records(1))
                    .await
                    .unwrap();

                let m_results = m_ctx
                    .try_join(
                        zip(
                            repeat(m_ctx.set_total_records(COUNT - 1)).enumerate(),
                            zip(m_input.iter(), m_input.iter().skip(1)),
                        )
                        .map(
                            |((i, ctx), (a_malicious, b_malicious))| async move {
                                a_malicious
                                    .multiply(b_malicious, ctx, RecordId::from(i))
                                    .await
                            },
                        ),
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
