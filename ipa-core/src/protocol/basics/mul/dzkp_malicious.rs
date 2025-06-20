use async_trait::async_trait;

use crate::{
    error::Error,
    ff::Field,
    protocol::{
        RecordId,
        basics::{SecureMul, mul::semi_honest::multiplication_protocol},
        context::{
            Context, DZKPUpgradedMaliciousContext, dzkp_field::DZKPCompatibleField,
            dzkp_validator::Segment,
        },
        prss::SharedRandomness,
    },
    secret_sharing::{Vectorizable, replicated::semi_honest::AdditiveShare as Replicated},
    sharding::{NotSharded, ShardBinding},
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
pub async fn zkp_multiply<B, F, const N: usize>(
    ctx: DZKPUpgradedMaliciousContext<'_, B>,
    record_id: RecordId,
    a: &Replicated<F, N>,
    b: &Replicated<F, N>,
) -> Result<Replicated<F, N>, Error>
where
    B: ShardBinding,
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
impl<'a, B: ShardBinding, F: Field + DZKPCompatibleField<N>, const N: usize>
    SecureMul<DZKPUpgradedMaliciousContext<'a, B>> for Replicated<F, N>
{
    async fn multiply<'fut>(
        &self,
        rhs: &Self,
        ctx: DZKPUpgradedMaliciousContext<'a, B>,
        record_id: RecordId,
    ) -> Result<Self, Error>
    where
        DZKPUpgradedMaliciousContext<'a, NotSharded>: 'fut,
    {
        zkp_multiply(ctx, record_id, self, rhs).await
    }
}

#[cfg(all(test, unit_test))]
mod test {
    use crate::{
        ff::boolean::Boolean,
        protocol::{
            RecordId,
            basics::SecureMul,
            context::{Context, TEST_DZKP_STEPS, UpgradableContext, dzkp_validator::DZKPValidator},
        },
        rand::{Rng, thread_rng},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    #[tokio::test]
    pub async fn simple() {
        let world = TestWorld::default();

        let mut rng = thread_rng();
        let a = rng.r#gen::<Boolean>();
        let b = rng.r#gen::<Boolean>();

        let res = world
            .malicious((a, b), |ctx, (a, b)| async move {
                let validator = ctx.dzkp_validator(TEST_DZKP_STEPS, 8);
                let mctx = validator.context();
                let result = a
                    .multiply(&b, mctx.set_total_records(1), RecordId::from(0))
                    .await
                    .unwrap();

                // validate all elements in the batch
                validator.validate().await.unwrap();

                result
            })
            .await;

        assert_eq!(a * b, res.reconstruct());
    }
}
