use crate::error::BoxError;
use crate::ff::Field;
use crate::protocol::{context::ProtocolContext, mul::SecureMul, RecordId};
use crate::secret_sharing::Replicated;

/// Secure XOR protocol with two inputs, `a, b ∈ {0,1} ⊆ F_p`.
/// It computes `[a] + [b] - 2[ab]`
pub struct Xor<F: Field> {
    a: Replicated<F>,
    b: Replicated<F>,
}

impl<'a, F: Field> Xor<F> {
    #[allow(dead_code)]
    pub fn new(a: Replicated<F>, b: Replicated<F>) -> Self {
        Self { a, b }
    }

    #[allow(dead_code)]
    pub async fn execute(
        &self,
        ctx: ProtocolContext<'_, Replicated<F>, F>,
        record_id: RecordId,
    ) -> Result<Replicated<F>, BoxError> {
        let ab = ctx.multiply(record_id, self.a, self.b).await?;
        Ok(self.a + self.b - (ab * F::from(2)))
    }
}

#[cfg(test)]
mod tests {
    use super::Xor;
    use crate::{
        error::BoxError,
        ff::{Field, Fp31},
        protocol::{QueryId, RecordId},
        test_fixture::{make_contexts, make_world, share, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use rand::rngs::mock::StepRng;

    async fn xor(a: Fp31, b: Fp31) -> Result<Fp31, BoxError> {
        let world: TestWorld = make_world(QueryId);
        let ctx = make_contexts::<Fp31>(&world);
        let mut rand = StepRng::new(1, 1);

        // Generate secret shares
        #[allow(clippy::type_complexity)]
        let a_shares = share(a, &mut rand);
        let b_shares = share(b, &mut rand);

        // Execute
        let step = "Xor_Test";
        let result = try_join_all(vec![
            Xor::new(a_shares[0], b_shares[0]).execute(ctx[0].narrow(step), RecordId::from(0_u32)),
            Xor::new(a_shares[1], b_shares[1]).execute(ctx[1].narrow(step), RecordId::from(0_u32)),
            Xor::new(a_shares[2], b_shares[2]).execute(ctx[2].narrow(step), RecordId::from(0_u32)),
        ])
        .await
        .unwrap();

        Ok(validate_and_reconstruct((result[0], result[1], result[2])))
    }

    #[tokio::test]
    pub async fn basic() -> Result<(), BoxError> {
        assert_eq!(Fp31::ZERO, xor(Fp31::ZERO, Fp31::ZERO).await?);
        assert_eq!(Fp31::ONE, xor(Fp31::ONE, Fp31::ZERO).await?);
        assert_eq!(Fp31::ONE, xor(Fp31::ZERO, Fp31::ONE).await?);
        assert_eq!(Fp31::ZERO, xor(Fp31::ONE, Fp31::ONE).await?);

        Ok(())
    }
}
