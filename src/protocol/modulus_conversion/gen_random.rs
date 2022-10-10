use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        mesh::{Gateway, Mesh},
        prss::SpaceIndex,
        Identity,
    },
    protocol::{context::ProtocolContext, IPAProtocolStep, ModulusConversionStep, RecordId, Step},
    secret_sharing::Replicated,
};
use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've reshared their own shares
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct ReplicatedBinary(bool, bool);

impl ReplicatedBinary {
    #[must_use]
    pub fn new(a: bool, b: bool) -> Self {
        Self(a, b)
    }
}

/// GenRandom(i, \[x\])
#[derive(Debug)]
pub struct GenRandom {
    input: ReplicatedBinary,
}

impl GenRandom {
    #[allow(dead_code)]
    pub fn new(input: ReplicatedBinary) -> Self {
        Self { input }
    }

    fn local_secret_share<F: Field>(
        input: ReplicatedBinary,
        channel_identity: Identity,
    ) -> (Replicated<F>, Replicated<F>, Replicated<F>)
    where
        F: Field,
    {
        match channel_identity {
            Identity::H1 => (
                Replicated::new(F::from(input.0 as u128), F::ZERO),
                Replicated::new(F::ZERO, F::from(input.1 as u128)),
                Replicated::new(F::ZERO, F::ZERO),
            ),
            Identity::H2 => (
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(input.0 as u128), F::ZERO),
                Replicated::new(F::ZERO, F::from(input.1 as u128)),
            ),
            Identity::H3 => (
                Replicated::new(F::ZERO, F::from(input.1 as u128)),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(input.0 as u128), F::ZERO),
            ),
        }
    }

    async fn xor<F: Field, M: Mesh, G: Gateway<M, IPAProtocolStep>>(
        a: Replicated<F>,
        b: Replicated<F>,
        ctx: &ProtocolContext<'_, G, IPAProtocolStep>,
        step: IPAProtocolStep,
        record_id: RecordId,
    ) -> Result<Replicated<F>, BoxError> {
        let result = ctx.multiply(record_id, step).await.execute(a, b).await?;

        Ok(a + b - (result * F::from(2)))
    }

    #[allow(dead_code)]
    pub async fn execute<F: Field, M: Mesh, G: Gateway<M, S>, S: Step + SpaceIndex>(
        &self,
        ctx: &ProtocolContext<'_, G, S>,
        record_id: RecordId,
    ) -> Result<Replicated<F>, BoxError>
    where
        F: Field,
    {
        let channel = ctx.gateway.get_channel(IPAProtocolStep::ConvertShares(
            ModulusConversionStep::Share0XORShare1,
        ));
        let (sh0, sh1, sh2) = Self::local_secret_share(self.input, channel.identity());

        let sh0_xor_sh1 = Self::xor(
            sh0,
            sh1,
            ctx,
            IPAProtocolStep::ConvertShares(ModulusConversionStep::Share0XORShare1),
            record_id,
        )
        .await?;
        Ok(Self::xor(
            sh0_xor_sh1,
            sh2,
            ctx,
            IPAProtocolStep::ConvertShares(ModulusConversionStep::ResultXORShare2),
            record_id,
        )
        .await?)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use rand::rngs::mock::StepRng;
    use tokio::try_join;

    use crate::{
        protocol::{
            modulus_conversion::gen_random::{GenRandom, ReplicatedBinary},
            QueryId, RecordId,
        },
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestStep, TestWorld},
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

            let input = (b0 ^ b1) ^ b2;

            let gen_random0 = GenRandom::new(ReplicatedBinary::new(b0, b1));
            let gen_random1 = GenRandom::new(ReplicatedBinary::new(b1, b2));
            let gen_random2 = GenRandom::new(ReplicatedBinary::new(b2, b0));

            let h0_future = gen_random0.execute(&context[0], record_id);
            let h1_future = gen_random1.execute(&context[1], record_id);
            let h2_future = gen_random2.execute(&context[2], record_id);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            let output_share = validate_and_reconstruct(f);
            assert_eq!(output_share, input);
        }
    }
}
