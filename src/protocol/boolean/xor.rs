use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::Context;
use crate::protocol::mul::{MultiplyZeroPositions, ZeroPositions};
use crate::protocol::RecordId;
use crate::secret_sharing::SecretSharing;

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
/// # Errors
/// When communication fails.
pub async fn xor<F, C, S>(ctx: C, record_id: RecordId, a: &S, b: &S) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    xor_sparse(ctx, record_id, a, b, ZeroPositions::NONE).await
}

/// Secure XOR protocol with maybe sparse inputs.
/// # Errors
/// When communication fails.
pub async fn xor_sparse<F, C, S>(
    ctx: C,
    record_id: RecordId,
    a: &S,
    b: &S,
    zeros_at: MultiplyZeroPositions,
) -> Result<S, Error>
where
    F: Field,
    C: Context<F, Share = S>,
    S: SecretSharing<F>,
{
    let ab = ctx.multiply_sparse(record_id, a, b, zeros_at).await?;
    Ok(-(ab * F::from(2)) + a + b)
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::xor;
    use crate::{
        ff::{Field, Fp32BitPrime},
        protocol::{QueryId, RecordId},
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
                xor(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .malicious((a, b), |ctx, (a_share, b_share)| async move {
                xor(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);
        result
    }

    #[tokio::test]
    pub async fn all_combinations() {
        type F = Fp32BitPrime;

        let world = TestWorld::new(QueryId);

        assert_eq!(F::ZERO, run(&world, F::ZERO, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ZERO, F::ONE).await);
        assert_eq!(F::ZERO, run(&world, F::ONE, F::ONE).await);
    }
}
