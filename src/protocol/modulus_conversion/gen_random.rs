use crate::{
    error::{BoxError, Error},
    field::Field,
    helpers::{fabric::Network, prss::SpaceIndex, Identity},
    protocol::{context::ProtocolContext, RecordId, Step},
    secret_sharing::Replicated,
};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

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

impl ModulusConversionStep {
    const XOR1_STR: &'static str = "xor1";
    const XOR2_STR: &'static str = "xor2";
}

impl Display for ModulusConversionStep {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Xor1 => write!(f, "{}", Self::XOR1_STR),
            Self::Xor2 => write!(f, "{}", Self::XOR2_STR),
        }
    }
}

impl TryFrom<String> for ModulusConversionStep {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            Self::XOR1_STR => Ok(Self::Xor1),
            Self::XOR2_STR => Ok(Self::Xor2),
            other => Err(Error::path_parse_error(other)),
        }
    }
}

impl Step for ModulusConversionStep {}

///
/// This file is an implementation of Algorithm D.3 from <https://eprint.iacr.org/2018/387.pdf>
/// "Efficient generation of a pair of random shares for small number of parties"
///
/// In order to convert from a 3-party secret sharing in `Z_2`, to a 3-party replicated
/// secret sharing in `Z_p` (where p > 2), we need to generate two secret sharings of
/// a random value `r` ∈ {0, 1}, where none of the helper parties know the value of `r`.
/// With Psuedo-random secret-sharing (PRSS), we can generate a 3-party replicated
/// secret-sharing of unknown value 'r' without any interaction between the helpers.
/// We just generate 3 random binary inputs, where each helper is aware of just two.
///
/// This `GenRandom` protocol takes as input such a 3-way random binary replicated secret-sharing,
/// and produces a 3-party replicated secret-sharing of the same value in a target field
/// of the caller's choosing.
/// Example:
/// For input binary sharing: (0, 1, 1) -> which is a sharing of 0 in `Z_2`
/// sample output in `Z_31` could be: (22, 19, 21) -> also a sharing of 0 in `Z_31`
/// This transformation is simple:
/// The original can be conceived of as r = b0 ⊕ b1 ⊕ b2
/// Each of the 3 bits can be trivially converted into a 3-way secret sharing in `Z_p`
/// So if the second bit is a '1', we can make a 3-way secret sharing of '1' in `Z_p`
/// as (0, 1, 0).
/// Now we simply need to XOR these three sharings together in `Z_p`. This is easy because
/// we know the secret-shared values are all either 0, or 1. As such, the XOR operation
/// is equivalent to fn xor(a, b) { a + b - 2*a*b }
#[derive(Debug)]
pub struct GenRandom {
    input: ReplicatedBinary,
}

impl GenRandom {
    #[allow(dead_code)]
    pub fn new(input: ReplicatedBinary) -> Self {
        Self { input }
    }

    ///
    /// Internal use only.
    /// This is an implementation of "Algorithm 3" from <https://eprint.iacr.org/2018/387.pdf>
    ///
    fn local_secret_share<F: Field>(
        input: ReplicatedBinary,
        channel_identity: Identity,
    ) -> (Replicated<F>, Replicated<F>, Replicated<F>) {
        match channel_identity {
            Identity::H1 => (
                Replicated::new(F::from(u128::from(input.0)), F::ZERO),
                Replicated::new(F::ZERO, F::from(u128::from(input.1))),
                Replicated::new(F::ZERO, F::ZERO),
            ),
            Identity::H2 => (
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(u128::from(input.0)), F::ZERO),
                Replicated::new(F::ZERO, F::from(u128::from(input.1))),
            ),
            Identity::H3 => (
                Replicated::new(F::ZERO, F::from(u128::from(input.1))),
                Replicated::new(F::ZERO, F::ZERO),
                Replicated::new(F::from(u128::from(input.0)), F::ZERO),
            ),
        }
    }

    ///
    /// Internal use only
    /// When both inputs are known to be secret share of either '1' or '0',
    /// XOR can be computed as:
    /// a + b - 2*a*b
    ///
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

    ///
    /// This will convert the input (a random, replicated binary secret sharing
    /// of unknown number 'r') into a random secret sharing of the same value in `Z_p`
    /// where the caller can select the output Field.
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
        Self::xor(sh0_xor_sh1, sh2, ctx, step2, record_id).await
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        error::{BoxError, Error},
        field::{Field, Fp31},
        protocol::{
            modulus_conversion::gen_random::{GenRandom, ModulusConversionStep, ReplicatedBinary},
            QueryId, RecordId, SpaceIndex, Step,
        },
        test_fixture::{make_contexts, make_world, validate_and_reconstruct, TestWorld},
    };
    use futures::future::try_join_all;
    use proptest::prelude::Rng;
    use std::fmt::{Display, Formatter};
    use tokio::try_join;

    #[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
    struct ModulusConversionTestStep {
        bit_number: u8,
        internal_step: ModulusConversionStep,
    }

    impl Display for ModulusConversionTestStep {
        fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}/{}", self.internal_step, self.bit_number)
        }
    }

    impl TryFrom<String> for ModulusConversionTestStep {
        type Error = Error;

        fn try_from(value: String) -> Result<Self, Self::Error> {
            let value = value.strip_prefix('/').unwrap_or(&value).to_lowercase();
            if let Some((internal_step, bit_number)) = value.split_once('/') {
                Ok(ModulusConversionTestStep {
                    bit_number: bit_number.parse()?,
                    internal_step: internal_step.to_owned().try_into()?,
                })
            } else {
                Err(Error::path_parse_error(&value))
            }
        }
    }

    impl Step for ModulusConversionTestStep {}

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
    pub async fn gen_random() -> Result<(), BoxError> {
        let mut rng = rand::thread_rng();

        let world: TestWorld<ModulusConversionTestStep> = make_world(QueryId);
        let context = make_contexts(&world);
        let ctx0 = &context[0];
        let ctx1 = &context[1];
        let ctx2 = &context[2];

        let mut bools: Vec<u128> = Vec::with_capacity(40);

        let inputs = (0..40).into_iter().map(|_i| {
            let b0 = rng.gen::<bool>();
            let b1 = rng.gen::<bool>();
            let b2 = rng.gen::<bool>();
            bools.push(u128::from((b0 ^ b1) ^ b2));

            (
                GenRandom::new(ReplicatedBinary::new(b0, b1)),
                GenRandom::new(ReplicatedBinary::new(b1, b2)),
                GenRandom::new(ReplicatedBinary::new(b2, b0)),
            )
        });

        let futures = inputs
            .into_iter()
            .enumerate()
            .map(|(index, (gr0, gr1, gr2))| async move {
                let index_bytes: [u8; 8] = index.to_le_bytes();
                let i = index_bytes[0];
                let record_id = RecordId::from(0_u32);
                let step1 = ModulusConversionTestStep {
                    bit_number: i,
                    internal_step: ModulusConversionStep::Xor1,
                };
                let step2 = ModulusConversionTestStep {
                    bit_number: i,
                    internal_step: ModulusConversionStep::Xor2,
                };

                let f0 = gr0.execute(ctx0, record_id, step1, step2);
                let f1 = gr1.execute(ctx1, record_id, step1, step2);
                let f2 = gr2.execute(ctx2, record_id, step1, step2);

                try_join!(f0, f1, f2)
            });

        let awaited_futures = try_join_all(futures).await?;

        for i in 0..40 {
            let output_share: Fp31 = validate_and_reconstruct(awaited_futures[i]);

            assert_eq!(output_share.as_u128(), bools[i]);
        }
        Ok(())
    }
}
