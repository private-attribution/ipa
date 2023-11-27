use crate::{
    error::Error,
    ff::Field,
    protocol::{
        basics::{MultiplyZeroPositions, SecureMul, ZeroPositions},
        context::Context,
        RecordId,
    },
    secret_sharing::Linear as LinearSecretSharing,
};

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
/// # Errors
/// When communication fails.
pub async fn xor<F, C, S>(ctx: C, record_id: RecordId, a: &S, b: &S) -> Result<S, Error>
where
    F: Field,
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
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
    C: Context,
    S: LinearSecretSharing<F> + SecureMul<C>,
{
    let ab = a.multiply_sparse(b, ctx, record_id, zeros_at).await?;
    Ok(-(ab * F::truncate_from(2_u128)) + a + b)
}

#[cfg(all(test, unit_test))]
mod tests {
    use rand::distributions::{Distribution, Standard};

    use super::xor;
    use crate::{
        ff::{Field, Fp31, Fp32BitPrime},
        protocol::{
            basics::{mul::sparse::test::SparseField, MultiplyZeroPositions, ZeroPositions},
            boolean::xor_sparse,
            context::Context,
            RecordId,
        },
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
                xor(
                    ctx.set_total_records(1),
                    RecordId::from(0),
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
                xor(
                    ctx.set_total_records(1),
                    RecordId::from(0),
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

    /// Run all combinations of XOR.
    /// Note that this is redundant with the `all_sparse()` below, but it uses
    /// a larger field and is simpler to reason about.
    #[tokio::test]
    pub async fn all_combinations() {
        type F = Fp32BitPrime;

        let world = TestWorld::default();

        assert_eq!(F::ZERO, run(&world, F::ZERO, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ONE, F::ZERO).await);
        assert_eq!(F::ONE, run(&world, F::ZERO, F::ONE).await);
        assert_eq!(F::ZERO, run(&world, F::ONE, F::ONE).await);
    }

    async fn run_sparse(world: &TestWorld, a: bool, b: bool, zeros: MultiplyZeroPositions) -> bool {
        type F = Fp31;

        let a = SparseField::<F>::new(F::truncate_from(u128::from(a)), zeros.0);
        let b = SparseField::<F>::new(F::truncate_from(u128::from(b)), zeros.1);
        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                xor_sparse(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    &b_share,
                    zeros,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        let m_result = world
            .upgraded_malicious((a, b), |ctx, (a_share, b_share)| async move {
                xor_sparse(
                    ctx.set_total_records(1),
                    RecordId::from(0),
                    &a_share,
                    &b_share,
                    zeros,
                )
                .await
                .unwrap()
            })
            .await
            .reconstruct();

        assert_eq!(result, m_result);
        assert!(result.as_u128() <= 1);
        result == F::ONE
    }

    /// Run all XOR operations with all combinations of sparse inputs.
    #[tokio::test]
    pub async fn all_sparse() {
        let world = TestWorld::default();

        for &a in ZeroPositions::all() {
            for &b in ZeroPositions::all() {
                if ZeroPositions::is_pointless((a, b)) {
                    continue; // Skip a test that should panic.
                }

                assert!(!run_sparse(&world, false, false, (a, b)).await);
                assert!(run_sparse(&world, true, false, (a, b)).await);
                assert!(run_sparse(&world, false, true, (a, b)).await);
                assert!(!run_sparse(&world, true, true, (a, b)).await);
            }
        }
    }
}
