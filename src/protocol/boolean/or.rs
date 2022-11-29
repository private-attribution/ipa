use crate::error::Error;
use crate::ff::Field;
use crate::protocol::context::Context;
use crate::protocol::{mul::SecureMul, RecordId};
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
