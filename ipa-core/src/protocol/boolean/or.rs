use crate::{
    error::Error,
    ff::Field,
    protocol::{basics::SecureMul, context::Context, RecordId},
    secret_sharing::Linear as LinearSecretSharing,
};

/// Secure OR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - [ab]`
///
/// ## Errors
/// Fails if the multiplication protocol fails.
pub async fn or<F: Field, C: Context, S: LinearSecretSharing<F> + SecureMul<C>>(
    ctx: C,
    record_id: RecordId,
    a: &S,
    b: &S,
) -> Result<S, Error> {
    let ab = a.multiply(b, ctx, record_id).await?;
    Ok(-ab + a + b)
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::distributions::{Distribution, Standard};

    use super::or;
    use crate::{
        ff::{Field, Fp31},
        protocol::{context::Context, RecordId},
        secret_sharing::{replicated::malicious::ExtendableField, SharedValue},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    async fn run<F>(world: &TestWorld, a: F, b: F) -> F
    where
        F: ExtendableField,
        Standard: Distribution<F>,
    {
        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                or(
                    ctx.set_total_records(1),
                    RecordId::from(0_u32),
                    &a_share,
                    &b_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();
        let m_result = world
            .upgraded_malicious((a, b), |ctx, (a_share, b_share)| async move {
                or(
                    ctx.set_total_records(1),
                    RecordId::from(0_u32),
                    &a_share,
                    &b_share,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);
        result
    }

    #[tokio::test]
    pub async fn all() {
        type F = Fp31;
        let world = TestWorld::default();

        assert_eq!(F::ZERO, run(&world, F::ZERO, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ZERO, F::ONE).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ONE).await);
    }
}
