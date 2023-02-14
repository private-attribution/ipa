use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::Context;
use crate::protocol::RecordId;
use crate::secret_sharing::SecretSharing;

/// Secure OR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - [ab]`
pub async fn or<F: Field, C: Context<F, Share = S>, S: SecretSharing<F>>(
    ctx: C,
    record_id: RecordId,
    a: &S,
    b: &S,
) -> Result<S, Error> {
    let ab = ctx.multiply(record_id, a, b).await?;
    Ok(-ab + a + b)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::or;
    use crate::{
        ff::{Field, Fp31},
        protocol::{context::Context, RecordId},
        secret_sharing::SharedValue,
        test_fixture::{Reconstruct, Runner, TestWorld},
    };
    use rand::distributions::{Distribution, Standard};

    async fn run<F>(world: &TestWorld, a: F, b: F) -> F
    where
        F: Field,
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
            .malicious((a, b), |ctx, (a_share, b_share)| async move {
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
        let world = TestWorld::new().await;

        assert_eq!(F::ZERO, run(&world, F::ZERO, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ZERO, F::ONE).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ONE).await);
    }
}
