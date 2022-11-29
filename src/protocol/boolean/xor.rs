use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
pub async fn xor<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    let ab = ctx.multiply(record_id, a, b).await?;
    Ok(a + b - &(ab * F::from(2)))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::xor;
    use crate::{
        ff::{Field, Fp31},
        protocol::{QueryId, RecordId},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    async fn xor_fp31(world: &TestWorld<Fp31>, a: Fp31, b: Fp31) -> Fp31 {
        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                xor(ctx, RecordId::from(0), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;

        result.reconstruct()
    }

    #[tokio::test]
    pub async fn all_combinations() {
        let world = TestWorld::new(QueryId);

        assert_eq!(Fp31::ZERO, xor_fp31(&world, Fp31::ZERO, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, xor_fp31(&world, Fp31::ONE, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, xor_fp31(&world, Fp31::ZERO, Fp31::ONE).await);
        assert_eq!(Fp31::ZERO, xor_fp31(&world, Fp31::ONE, Fp31::ONE).await);
    }
}
