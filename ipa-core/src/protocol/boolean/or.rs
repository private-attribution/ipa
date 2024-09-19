use std::iter::zip;

use ipa_step::StepNarrow;

use crate::{
    error::Error,
    ff::{boolean::Boolean, Field},
    protocol::{basics::SecureMul, boolean::NBitStep, context::Context, Gate, RecordId},
    secret_sharing::{
        replicated::semi_honest::AdditiveShare, BitDecomposed, FieldSimd,
        Linear as LinearSecretSharing,
    },
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

/// Matrix bitwise OR for use with vectors of bit-decomposed values
///
/// ## Errors
/// Propagates errors from the multiplication protocol.
/// ## Panics
/// Panics if the bit-decomposed arguments do not have the same length.
//
// Supplying an iterator saves constructing a complete copy of the argument
// in memory when it is a uniform constant.
pub async fn bool_or<'a, C, S, BI, const N: usize>(
    ctx: C,
    record_id: RecordId,
    a: &BitDecomposed<AdditiveShare<Boolean, N>>,
    b: BI,
) -> Result<BitDecomposed<AdditiveShare<Boolean, N>>, Error>
where
    C: Context,
    S: NBitStep,
    BI: IntoIterator,
    <BI as IntoIterator>::IntoIter: ExactSizeIterator<Item = &'a AdditiveShare<Boolean, N>> + Send,
    Boolean: FieldSimd<N>,
    AdditiveShare<Boolean, N>: SecureMul<C>,
    Gate: StepNarrow<S>,
{
    let b = b.into_iter();
    assert_eq!(a.len(), b.len());

    BitDecomposed::try_from(
        ctx.parallel_join(zip(a.iter(), b).enumerate().map(|(i, (a, b))| {
            let ctx = ctx.narrow(&S::from(i));
            async move {
                let ab = a.multiply(b, ctx, record_id).await?;
                Ok::<_, Error>(-ab + a + b)
            }
        }))
        .await?,
    )
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
            .upgraded_malicious(
                vec![(a, b)].into_iter(),
                |ctx, record_id, (a_share, b_share)| async move {
                    or(ctx, record_id, &a_share, &b_share).await.unwrap()
                },
            )
            .await
            .reconstruct();

        assert_eq!(result, m_result[0]);
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
