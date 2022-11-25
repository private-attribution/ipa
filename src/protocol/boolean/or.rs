use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::{context::Context, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
pub async fn or<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    record_id: RecordId,
    a: &Replicated<F>,
    b: &Replicated<F>,
) -> Result<Replicated<F>, Error> {
    let one = Replicated::one(ctx.role());
    let result = ctx.multiply(record_id, &(&one - a), &(&one - b)).await?;
    Ok(one - &result)
}

#[cfg(test)]
mod tests {
    use super::or;
    use crate::{
        ff::{Field, Fp31},
        protocol::{QueryId, RecordId},
        test_fixture::{Reconstruct, Runner, TestWorld},
    };

    async fn or_fp31(a: Fp31, b: Fp31) -> Fp31 {
        let world = TestWorld::new(QueryId);

        let result = world
            .semi_honest((a, b), |ctx, (a_share, b_share)| async move {
                or(ctx, RecordId::from(0_u32), &a_share, &b_share)
                    .await
                    .unwrap()
            })
            .await;
        result.reconstruct()
    }

    #[tokio::test]
    pub async fn basic() {
        assert_eq!(Fp31::ZERO, or_fp31(Fp31::ZERO, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ONE, Fp31::ZERO).await);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ZERO, Fp31::ONE).await);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ONE, Fp31::ONE).await);
    }
}
