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
    use crate::protocol::context::Context;
    use crate::{
        error::Error,
        ff::{Field, Fp31},
        protocol::{QueryId, RecordId},
        test_fixture::{share, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::rngs::mock::StepRng;

    async fn or_fp31(a: Fp31, b: Fp31) -> Result<Fp31, Error> {
        let world = TestWorld::new(QueryId);
        let ctx = world.contexts::<Fp31>();
        let mut rand = StepRng::new(1, 1);

        // Generate secret shares
        #[allow(clippy::type_complexity)]
        let a_shares = share(a, &mut rand);
        let b_shares = share(b, &mut rand);

        // Execute
        let step = "Or_Test";
        let result = try_join_all(vec![
            or(
                ctx[0].narrow(step),
                RecordId::from(0_u32),
                &a_shares[0],
                &b_shares[0],
            ),
            or(
                ctx[1].narrow(step),
                RecordId::from(0_u32),
                &a_shares[1],
                &b_shares[1],
            ),
            or(
                ctx[2].narrow(step),
                RecordId::from(0_u32),
                &a_shares[2],
                &b_shares[2],
            ),
        ])
        .await
        .unwrap();

        Ok(validate_and_reconstruct(&result[0], &result[1], &result[2]))
    }

    #[tokio::test]
    pub async fn basic() -> Result<(), Error> {
        assert_eq!(Fp31::ZERO, or_fp31(Fp31::ZERO, Fp31::ZERO).await?);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ONE, Fp31::ZERO).await?);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ZERO, Fp31::ONE).await?);
        assert_eq!(Fp31::ONE, or_fp31(Fp31::ONE, Fp31::ONE).await?);

        Ok(())
    }
}
