use crate::error::Error;
use crate::ff::Field;
use crate::protocol::{context::ProtocolContext, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
pub async fn or<F: Field>(
    ctx: ProtocolContext<'_, Replicated<F>, F>,
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
        error::Error,
        ff::{Field, Fp31},
        protocol::{context::ProtocolContext, QueryId, RecordId},
        secret_sharing::Replicated,
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::rngs::mock::StepRng;

    async fn or_fp31(
        ctx: [ProtocolContext<'_, Replicated<Fp31>, Fp31>; 3],
        record_id: RecordId,
        a: Fp31,
        b: Fp31,
    ) -> Result<Fp31, Error> {
        let [c0, c1, c2] = ctx;
        let mut rand = StepRng::new(1, 1);

        // Generate secret shares
        #[allow(clippy::type_complexity)]
        let a_shares = share(a, &mut rand);
        let b_shares = share(b, &mut rand);

        // Execute
        let result = try_join_all(vec![
            or(c0.bind(record_id), record_id, &a_shares[0], &b_shares[0]),
            or(c1.bind(record_id), record_id, &a_shares[1], &b_shares[1]),
            or(c2.bind(record_id), record_id, &a_shares[2], &b_shares[2]),
        ])
        .await
        .unwrap();

        Ok(validate_and_reconstruct(&result[0], &result[1], &result[2]))
    }

    #[tokio::test]
    pub async fn basic() -> Result<(), Error> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let [c0, c1, c2] = ctx;

        assert_eq!(
            Fp31::ZERO,
            or_fp31(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(0),
                Fp31::ZERO,
                Fp31::ZERO
            )
            .await?
        );
        assert_eq!(
            Fp31::ONE,
            or_fp31(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(1),
                Fp31::ONE,
                Fp31::ZERO
            )
            .await?
        );
        assert_eq!(
            Fp31::ONE,
            or_fp31(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(2),
                Fp31::ZERO,
                Fp31::ONE
            )
            .await?
        );
        assert_eq!(
            Fp31::ONE,
            or_fp31(
                [c0.clone(), c1.clone(), c2.clone()],
                RecordId::from(3),
                Fp31::ONE,
                Fp31::ONE
            )
            .await?
        );

        Ok(())
    }
}
