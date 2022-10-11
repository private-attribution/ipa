use crate::{
    error::BoxError,
    field::Field,
    helpers::{
        fabric::Network,
        prss::SpaceIndex,
        Identity,
    },
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};

use serde::{Deserialize, Serialize};

/// A message sent by each helper when they've reshared their own shares
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
pub struct ReplicatedBinary(bool, bool);

impl ReplicatedBinary {
    #[must_use]
    #[allow(dead_code)]
    pub fn new(a: bool, b: bool) -> Self {
        Self(a, b)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ModulusConversionStep {
    Xor1,
    Xor2,
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

    async fn xor<F: Field, S: Step + SpaceIndex, N: Network<S>>(
        a: Replicated<F>,
        b: Replicated<F>,
        ctx: &ProtocolContext<'_, S, N>,
        step: S,
        record_id: RecordId,
    ) -> Result<Replicated<F>, BoxError> {
        let result = ctx.multiply(record_id, step).await.execute(a, b).await?;

        Ok(a + b - (result * F::from(2)))
    }

    #[allow(dead_code)]
    pub async fn execute<F: Field, S: Step + SpaceIndex, N: Network<S>>(
        &self,
        ctx: &ProtocolContext<'_, S, N>,
        record_id: RecordId,
        step1: S,
        step2: S,
    ) -> Result<Replicated<F>, BoxError> {
        let (sh0, sh1, sh2) = Self::local_secret_share(self.input, ctx.identity);

        let sh0_xor_sh1 = Self::xor(sh0, sh1, ctx, step1, record_id).await?;
        Ok(Self::xor(sh0_xor_sh1, sh2, ctx, step2, record_id).await?)
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::Rng;
    use tokio::try_join;

    use crate::{
        field::{Field, Fp31},
        protocol::{
            modulus_conversion::gen_random::{GenRandom, ModulusConversionStep, ReplicatedBinary},
            QueryId, RecordId, SpaceIndex, Step,
        },
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestWorld},
    };

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        bit_number: u8,
        internal_step: ModulusConversionStep,
    }

    impl Step for ModulusConversionTestStep {
        // TODO
    }

    impl SpaceIndex for ModulusConversionTestStep {
        const MAX: usize = 512;

        fn as_usize(&self) -> usize {
            let b = self.bit_number as usize;
            match self.internal_step {
                ModulusConversionStep::Xor1 => b,
                ModulusConversionStep::Xor2 => 256_usize + b,
            }
        }
    }

    #[tokio::test]
    pub async fn gen_random() {
        let mut rng = rand::thread_rng();

        for _ in 0..10 {
            let record_id = RecordId::from(1);

            let world: TestWorld<ModulusConversionTestStep> = make_world(QueryId);
            let context = make_contexts(&world);

            let step1 = ModulusConversionTestStep {
                bit_number: 0,
                internal_step: ModulusConversionStep::Xor1,
            };
            let step2 = ModulusConversionTestStep {
                bit_number: 0,
                internal_step: ModulusConversionStep::Xor2,
            };

            let b0 = rng.gen::<u8>() >= 128;
            let b1 = rng.gen::<u8>() >= 128;
            let b2 = rng.gen::<u8>() >= 128;

            let input = ((b0 ^ b1) ^ b2) as u128;

            let gen_random0 = GenRandom::new(ReplicatedBinary::new(b0, b1));
            let gen_random1 = GenRandom::new(ReplicatedBinary::new(b1, b2));
            let gen_random2 = GenRandom::new(ReplicatedBinary::new(b2, b0));

            let h0_future = gen_random0.execute(&context[0], record_id, step1, step2);
            let h1_future = gen_random1.execute(&context[1], record_id, step1, step2);
            let h2_future = gen_random2.execute(&context[2], record_id, step1, step2);

            let f = try_join!(h0_future, h1_future, h2_future).unwrap();
            let output_share: Fp31 = validate_and_reconstruct(f);
            assert_eq!(output_share.as_u128(), input);
        }
    }
}
