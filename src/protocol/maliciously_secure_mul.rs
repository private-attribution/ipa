use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::fabric::Network;
use crate::protocol::{
    context::ProtocolContext, malicious::SecurityValidatorAccumulator, securemul::SecureMul,
    RecordId,
};
use crate::secret_sharing::MaliciousReplicated;
use futures::future::try_join;
use std::fmt::Debug;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Step {
    DuplicateMultiply,
    RandomnessForValidation,
}

impl crate::protocol::Step for Step {}

impl AsRef<str> for Step {
    fn as_ref(&self) -> &str {
        match self {
            Self::DuplicateMultiply => "duplicate_multiply",
            Self::RandomnessForValidation => "randomness_for_validation",
        }
    }
}

///
/// Implementation drawn from:
/// "Fast Large-Scale Honest-Majority MPC for Malicious Adversaries"
/// by by K. Chida, D. Genkin, K. Hamada, D. Ikarashi, R. Kikuchi, Y. Lindell, and A. Nof
/// <https://link.springer.com/content/pdf/10.1007/978-3-319-96878-0_2.pdf>
///
/// Protocol 5.3 "Computing Arithmetic Circuits Over Any Finite F"
/// Step 5: "Circuit Emulation"
/// (In our case, simplified slightly because δ=1)
/// When `G_k` is a multiplication gate:
/// Given tuples:  `([x], [r · x])` and `([y], [r · y])`
/// (a) The parties call `F_mult` on `[x]` and `[y]` to receive `[x · y]`
/// (b) The parties call `F_mult` on `[r · x]` and `[y]` to receive `[r · x · y]`.
///
/// As each multiplication gate affects Step 6: "Verification Stage", the Security Validator
/// must be provided. The two outputs of the multiplication, `[x · y]` and  `[r · x · y]`
/// will be provided to this Security Validator, and will update two information-theoretic MACs.
///
/// It's cricital that the functionality `F_mult` is secure up to an additive attack.
/// `SecureMult` is an implementation of the IKHC multiplication protocol, which has this property.
///
pub struct MaliciouslySecureMul<'a, N, F> {
    ctx: ProtocolContext<'a, N, F>,
    record_id: RecordId,
    accumulator: SecurityValidatorAccumulator<F>,
}

impl<'a, N: Network, F: Field> MaliciouslySecureMul<'a, N, F> {
    #[must_use]
    pub fn new(
        ctx: ProtocolContext<'a, N, F>,
        record_id: RecordId,
        accumulator: SecurityValidatorAccumulator<F>,
    ) -> Self {
        Self {
            ctx,
            record_id,
            accumulator,
        }
    }

    /// Executes two parallel multiplications;
    /// `A * B`, and `rA * B`, yielding both `AB` and `rAB`
    /// both `AB` and `rAB` are provided to the security validator
    ///
    /// ## Errors
    /// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
    /// back via the error response
    /// ## Panics
    /// Panics if the mutex is found to be poisoned
    pub async fn execute(
        self,
        a: MaliciousReplicated<F>,
        b: MaliciousReplicated<F>,
    ) -> Result<MaliciousReplicated<F>, BoxError> {
        // being clever and assuming a clean context...
        let duplicate_multiply_ctx = self.ctx.narrow(&Step::DuplicateMultiply);
        let random_constant_prss = self.ctx.narrow(&Step::RandomnessForValidation).prss();
        let (ab, rab) = try_join(
            SecureMul::new(self.ctx, self.record_id).execute(a.x(), b.x()),
            SecureMul::new(duplicate_multiply_ctx, self.record_id).execute(a.rx(), b.x()),
        )
        .await?;

        let malicious_ab = MaliciousReplicated::new(ab, rab);

        self.accumulator
            .accumulate_macs(random_constant_prss, self.record_id, malicious_ab);

        Ok(malicious_ab)
    }
}

#[cfg(test)]
pub mod tests {
    use crate::error::BoxError;
    use crate::field::Fp31;
    use crate::protocol::{
        malicious::SecurityValidator, maliciously_secure_mul::MaliciouslySecureMul, QueryId,
        RecordId,
    };
    use crate::secret_sharing::{MaliciousReplicated, Replicated};
    use crate::test_fixture::{
        logging, make_contexts, make_world, share, validate_and_reconstruct, TestWorld,
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
    /// To acheive malicious security, the entire circuit must be run twice, once with the original inputs,
    /// and once with all the inputs times a random, secret-shared value `r`. Two information theoretic MACs
    /// are updated; once for each input, and once for each multiplication. At the end of the circuit, these
    /// MACs are compared. If any helper deviated from the protocol, chances are that the MACs will not match up.
    /// There is a small chance of failure which is `2 / |F|`, where `|F|` is the cardinality of the prime field.
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
            let v = SecurityValidator::new(ctx.narrow("SecurityValidatorInit"));
            let acc = v.accumulator();
            let r_share = v.r_share();

            let (ra, rb) = try_join(
                ctx.narrow("mult1")
                    .multiply(RecordId::from(0))
                    .await
                    .execute(a_shares[i], r_share),
                ctx.narrow("mult2")
                    .multiply(RecordId::from(1))
                    .await
                    .execute(b_shares[i], r_share),
            )
            .await?;

            let a_malicious = MaliciousReplicated::new(a_shares[i], ra);
            let b_malicious = MaliciousReplicated::new(b_shares[i], rb);

            acc.accumulate_macs(
                ctx.narrow("validate_input1").prss(),
                RecordId::from(0),
                a_malicious,
            );
            acc.accumulate_macs(
                ctx.narrow("validate_input2").prss(),
                RecordId::from(1),
                b_malicious,
            );

            let malicious_ab =
                MaliciouslySecureMul::new(ctx.narrow("MultTogether"), RecordId::from(0), acc)
                    .execute(a_malicious, b_malicious)
                    .await?;

            v.validate(ctx.narrow("SecurityValidatorValidate")).await?;

            Ok::<(MaliciousReplicated<Fp31>, Replicated<Fp31>), BoxError>((malicious_ab, r_share))
        });

        let malicious_sharings = try_join_all(futures).await?;

        let r = validate_and_reconstruct((
            malicious_sharings[0].1,
            malicious_sharings[1].1,
            malicious_sharings[2].1,
        ));
        let ab = validate_and_reconstruct((
            malicious_sharings[0].0.x(),
            malicious_sharings[1].0.x(),
            malicious_sharings[2].0.x(),
        ));
        let rab = validate_and_reconstruct((
            malicious_sharings[0].0.rx(),
            malicious_sharings[1].0.rx(),
            malicious_sharings[2].0.rx(),
        ));
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
    /// To acheive malicious security, the entire circuit must be run twice, once with the original inputs,
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
                            let rx = record_narrowed_ctx
                                .narrow("mult")
                                .multiply(*record_id)
                                .await
                                .execute(*x, r_share)
                                .await?;
                            Ok::<MaliciousReplicated<Fp31>, BoxError>(MaliciousReplicated::new(
                                *x, rx,
                            ))
                        },
                    ))
                    .await?;

                    for i in 0..100 {
                        let (narrowed_ctx, record_id, _) = &inputs[i];
                        let rx = &rx_values[i];
                        acc.accumulate_macs(
                            narrowed_ctx.narrow("validate_input").prss(),
                            *record_id,
                            *rx,
                        );
                    }

                    let mut mult_inputs = Vec::with_capacity(99);
                    for i in 0..99 {
                        let (narrowed_ctx, record_id, _) = &inputs[i];
                        let malicious_a = &rx_values[i];
                        let malicious_b = &rx_values[i + 1];

                        mult_inputs.push((
                            narrowed_ctx,
                            *record_id,
                            acc.clone(),
                            *malicious_a,
                            *malicious_b,
                        ));
                    }

                    let _outputs = try_join_all(mult_inputs.iter().map(
                    |(narrowed_ctx, record_id, acc_clone, malicious_a, malicious_b)| async move {
                        MaliciouslySecureMul::new(
                            narrowed_ctx.narrow("SingleMult"),
                            *record_id,
                            acc_clone.clone(),
                        )
                        .execute(*malicious_a, *malicious_b)
                        .await
                    },
                ))
                .await?;

                    v.validate(ctx.narrow("SecurityValidatorValidate")).await
                });

        try_join_all(futures).await?;

        Ok(())
    }
}
