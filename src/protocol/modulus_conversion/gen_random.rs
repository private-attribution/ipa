use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        Identity,
    },
    protocol::{context::ProtocolContext, IPAProtocolStep, ModulusConversionStep, RecordId},
    secret_sharing::Replicated,
};
use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've reshared their own shares
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct ReplicatedBinary {
    left: bool,
    right: bool,
}
/// GenRandom(i, \[x\])
#[derive(Debug)]
pub struct GenRandom<F> {
    input: ReplicatedBinary,
}

impl<F: Field> GenRandom<F> {
    #[allow(dead_code)]
    pub fn new(input: ReplicatedBinary) -> Self {
        Self { input }
    }

    fn local_secret_share(
        input: ReplicatedBinary,
        channel_identity: Identity,
    ) -> (Replicated<F>, Replicated<F>, Replicated<F>)
    where
        F: Field,
    {
        match channel_identity() {
            Identity::H1 => (
                Replicated::new(F::from(input.left), F::ZERO),
                Replicated::new(F::ZERO, F::from(input.right)),
                Replicated::new(F::ZERO, F::ZERO),
            ),
            Identity::H2 => (
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(input.left), F::ZERO),
                Replicated::new(F::ZERO, F::from(input.right)),
            ),
            Identity::H3 => (
                Replicated::new(F::ZERO, F::from(input.right)),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(input.left), F::ZERO),
            ),
        }
    }

    async fn xor<M: Mesh, G: Gateway<M, IPAProtocolStep>>(
        a: Replicated<F>,
        b: Replicated<F>,
        ctx: &ProtocolContext<'_, G, IPAProtocolStep>,
        step: IPAProtocolStep,
        record_id: RecordId,
    ) -> Result<Replicated<F>, BoxError> {
        let result = ctx.multiply(record_id, step).await.execute(a, b).await?;

        a + b - (result * 2)
    }

    #[allow(dead_code)]
    pub async fn execute<M: Mesh, G: Gateway<M, IPAProtocolStep>>(
        &self,
        ctx: &ProtocolContext<'_, G, IPAProtocolStep>,
        record_id: RecordId,
    ) -> Result<Vec<Replicated<F>>, BoxError>
    where
        F: Field,
    {
        let mut channel = ctx.gateway.get_channel(IPAProtocolStep::ConvertShares(
            ModulusConversionStep::Share0XORShare1,
        ));
        let (sh0, sh1, sh2) = Self::local_secret_share(self.input, channel.identity());

        let sh0_xor_sh1 = Self::xor(
            sh0,
            sh1,
            ctx,
            IPAProtocolStep::ConvertShares(ModulusConversionStep::Share0XORShare1),
            record_id,
        )?;
        Self::xor(
            sh0_xor_sh1,
            sh2,
            ctx,
            IPAProtocolStep::ConvertShares(ModulusConversionStep::ResultXORShare2),
            record_id,
        )?
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        field::Fp31,
        helpers::Identity,
        test_fixture::{
            make_contexts, make_world, share, validate_and_reconstruct, TestStep, TestWorld,
        },
    };

    #[tokio::test]
    pub async fn gen_random() {
        let mut rand = StepRng::new(100, 1);
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let secret = rng.gen::<u128>();

            let record_id = RecordId::from(1);

            let world: TestWorld<TestStep> = make_world(QueryId);
            let context = make_contexts(&world);

            let step = TestStep::Reshare(1);

            let b0 = rng.gen() > 0.5;
            let b1 = rng.gen() > 0.5;
            let b2 = rng.gen() > 0.5;

            input = (b0 ^ b1) ^ b2;

            let gen_random0 = GenRandom::new(ReplicatedBinary { b0, b1 });
            let gen_random1 = GenRandom::new(ReplicatedBinary { b1, b2 });
            let gen_random2 = GenRandom::new(ReplicatedBinary { b2, b0 });

            let h0_future = gen_random0.execute(&context[0], record_id, step);
            let h1_future = gen_random1.execute(&context[1], record_id, step);
            let h2_future = gen_random2.execute(&context[2], record_id, step);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            let output_share = validate_and_reconstruct(f);
            assert_eq!(output_share, input);
        }
    }
}
