use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{mul::semi_honest::multiplication_protocol, SecureMul},
        context::{
            dzkp_field::DZKPCompatibleField, dzkp_validator::Segment, Context, DZKPContext,
            DZKPUpgradedMaliciousContext,
        },
        prss::SharedRandomness,
        RecordId,
    },
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, Vectorizable},
};

/// This function implements an MPC multiply using the standard strategy, i.e. via computing the
/// cross terms. It mirrors the semi-honest multiply but supports malicious contexts.
///
/// Different to the semi-honest multiply is that it collects intermediate terms in the `dzkp batch`.
/// These intermediate terms are then verified using a validator that has to be called either explicitly
/// or implicitly by using `ctx.seq_join`
///
/// ## Errors
/// Lots of things may go wrong here, from timeouts to bad output. They will be signalled
/// back via the error response
/// ## Panics
/// Panics if the mutex is found to be poisoned
pub async fn zkp_multiply<'a, F, const N: usize>(
    ctx: DZKPUpgradedMaliciousContext<'a>,
    record_id: RecordId,
    a: &Replicated<F, N>,
    b: &Replicated<F, N>,
) -> Result<Replicated<F, N>, Error>
where
    F: Field + DZKPCompatibleField<N>,
{
    // Shared randomness used to mask the values that are sent.
    let (prss_left, prss_right) = ctx
        .prss()
        .generate::<(<F as Vectorizable<N>>::Array, _), _>(record_id);

    let z = multiplication_protocol(&ctx, record_id, a, b, &prss_left, &prss_right).await?;

    // create segment
    let segment = Segment::from_entries(
        F::as_segment_entry(a.left_arr()),
        F::as_segment_entry(a.right_arr()),
        F::as_segment_entry(b.left_arr()),
        F::as_segment_entry(b.right_arr()),
        F::as_segment_entry(&prss_left),
        F::as_segment_entry(&prss_right),
        F::as_segment_entry(z.right_arr()),
    );

    // add segment to the batch that needs to be verified by the dzkp prover and verifiers
    ctx.push(record_id, segment);

    Ok(z)
}

/// Implement secure multiplication for malicious contexts with replicated secret sharing.
#[async_trait]
impl<'a, F: Field + DZKPCompatibleField<N>, const N: usize>
    SecureMul<DZKPUpgradedMaliciousContext<'a>> for Replicated<F, N>
{
    async fn multiply<'fut>(
        &self,
        rhs: &Self,
        ctx: DZKPUpgradedMaliciousContext<'a>,
        record_id: RecordId,
    ) -> Result<Self, Error>
    where
        DZKPUpgradedMaliciousContext<'a>: 'fut,
    {
        zkp_multiply(ctx, record_id, self, rhs).await
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use ipa_step_derive::CompactStep;

    use crate::{
        error::Error,
        ff::boolean::Boolean,
        helpers::{Role, Role::H1},
        protocol::{
            basics::{
                mul::{dzkp_malicious::Field, semi_honest::multiplication_protocol, Replicated},
                SecureMul,
            },
            context::{
                dzkp_field::DZKPCompatibleField,
                dzkp_validator::{DZKPValidator, Segment},
                Context, DZKPContext, DZKPUpgradedMaliciousContext, UpgradableContext,
            },
            RecordId,
        },
        rand::{thread_rng, Rng},
        secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValueArray, Vectorizable},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    /// This function mirrors `zkp_multiply` except that on party cheats.
    ///
    /// The cheating party flips `prss_left`
    /// which causes a flip in `z_left` computed by the cheating party.
    /// This manipulated `z_left` is then sent to a different helper
    /// and included in the DZKP batch.
    pub async fn multiply_with_cheater<'a, F, const N: usize>(
        ctx: DZKPUpgradedMaliciousContext<'a>,
        record_id: RecordId,
        a: &Replicated<F, N>,
        b: &Replicated<F, N>,
        prss: &Replicated<F, N>,
        cheater: Role,
    ) -> Result<Replicated<F, N>, Error>
    where
        F: Field + DZKPCompatibleField<N>,
    {
        let mut prss_left = prss.left_arr().clone();
        if ctx.role() == cheater {
            prss_left += <<F as Vectorizable<N>>::Array>::from_fn(|_| F::ONE);
        };

        let z =
            multiplication_protocol(&ctx, record_id, a, b, &prss_left, prss.right_arr()).await?;
        // create segment
        let segment = Segment::from_entries(
            F::as_segment_entry(a.left_arr()),
            F::as_segment_entry(a.right_arr()),
            F::as_segment_entry(b.left_arr()),
            F::as_segment_entry(b.right_arr()),
            F::as_segment_entry(prss.left_arr()),
            F::as_segment_entry(prss.right_arr()),
            F::as_segment_entry(z.right_arr()),
        );

        // add segment to the batch that needs to be verified by the dzkp prover and verifiers
        ctx.push(record_id, segment);

        Ok(z)
    }
    fn generate_share_from_three_bits(role: Role, i: usize) -> AdditiveShare<Boolean> {
        let (first_bit, second_bit) = match role {
            Role::H1 => (i % 2 == 0, (i >> 1) % 2 == 0),
            Role::H2 => ((i >> 1) % 2 == 0, (i >> 2) % 2 == 0),
            Role::H3 => ((i >> 2) % 2 == 0, i % 2 == 0),
        };
        <AdditiveShare<Boolean>>::from((first_bit.into(), second_bit.into()))
    }

    fn all_combination_of_inputs(role: Role, i: usize) -> [AdditiveShare<Boolean>; 3] {
        // first three bits
        let a = generate_share_from_three_bits(role, i);
        // middle three bits
        let b = generate_share_from_three_bits(role, i >> 3);
        // last three bits
        let prss = generate_share_from_three_bits(role, i >> 6);

        [a, b, prss]
    }

    #[derive(CompactStep)]
    enum TestStep {
        #[step(count = 512)]
        Counter(usize),
    }

    #[tokio::test]
    async fn detect_cheating() {
        let world = TestWorld::default();

        for i in 0..512 {
            let [(_, s_1), (_, s_2), (v_3, s_3)] = world
                .malicious((), |ctx, ()| async move {
                    let [a, b, prss] = all_combination_of_inputs(ctx.role(), i);
                    let validator = ctx.narrow(&TestStep::Counter(i)).dzkp_validator(10);
                    let mctx = validator.context();
                    let product = multiply_with_cheater(
                        mctx.set_total_records(1),
                        RecordId::FIRST,
                        &a,
                        &b,
                        &prss,
                        H1,
                    )
                    .await
                    .unwrap();

                    (
                        validator.validate().await,
                        [
                            bool::from(*a.left_arr().first()),
                            bool::from(*a.right_arr().first()),
                            bool::from(*b.left_arr().first()),
                            bool::from(*b.right_arr().first()),
                            bool::from(*prss.left_arr().first()),
                            bool::from(*prss.right_arr().first()),
                            bool::from(*product.left_arr().first()),
                            bool::from(*product.right_arr().first()),
                        ],
                    )
                })
                .await;

            // H1 cheats means H3 fails
            // since always verifier on the left of the cheating prover fails
            match v_3 {
                Ok(()) => panic!("Got a result H1: {s_1:?}, H2: {s_2:?}, H3: {s_3:?}"),
                Err(ref err) => assert!(matches!(err, Error::DZKPValidationFailed)),
            }
        }
    }

    #[tokio::test]
    async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.gen::<Boolean>();
        let b = rng.gen::<Boolean>();

        let res = world
            .malicious((a, b), |ctx, (a, b)| async move {
                let validator = ctx.dzkp_validator(10);
                let mctx = validator.context();
                let result = a
                    .multiply(&b, mctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap();

                // batch contains elements
                assert!(matches!(mctx.is_verified(), Err(Error::ContextUnsafe(_))));

                // validate all elements in the batch
                validator.validate().await.unwrap();

                // batch is empty now
                assert!(mctx.is_verified().is_ok());

                result
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }
}
