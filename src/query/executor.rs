use crate::{
    ff::{Field, GaloisField, Serializable},
    helpers::{
        negotiate_prss,
        query::{QueryConfig, QueryType},
        ByteArrStream, Gateway,
    },
    protocol::{
        attribution::input::MCAggregateCreditOutputRow,
        context::SemiHonestContext,
        step::{Gate, StepNarrow},
    },
    query::runner::IpaRunner,
    secret_sharing::{replicated::semi_honest::AdditiveShare, Linear as LinearSecretSharing},
    task::JoinHandle,
};
use generic_array::GenericArray;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use std::fmt::Debug;
use typenum::Unsigned;

pub trait Result: Send + Debug {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<F: Field> Result for Vec<AdditiveShare<F>>
where
    AdditiveShare<F>: Serializable,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * <AdditiveShare<F> as Serializable>::Size::USIZE];
        for (i, share) in self.into_iter().enumerate() {
            share.serialize(GenericArray::from_mut_slice(
                &mut r[i * <AdditiveShare<F> as Serializable>::Size::USIZE
                    ..(i + 1) * <AdditiveShare<F> as Serializable>::Size::USIZE],
            ));
        }

        r
    }
}

impl<F: Field, T: LinearSecretSharing<F>, BK: GaloisField> Result
    for Vec<MCAggregateCreditOutputRow<F, T, BK>>
where
    T: Serializable,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * MCAggregateCreditOutputRow::<F, T, BK>::SIZE];
        for (i, row) in self.into_iter().enumerate() {
            row.serialize(
                &mut r[MCAggregateCreditOutputRow::<F, T, BK>::SIZE * i
                    ..MCAggregateCreditOutputRow::<F, T, BK>::SIZE * (i + 1)],
            );
        }

        r
    }
}

#[allow(unused)]
pub fn start_query(
    config: QueryConfig,
    gateway: Gateway,
    input: ByteArrStream,
) -> JoinHandle<Box<dyn Result>> {
    tokio::spawn(async move {
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS first
        let gate = Gate::default().narrow(&config.query_type);
        let prss = negotiate_prss(&gateway, &gate, &mut rng).await.unwrap();
        let ctx = SemiHonestContext::new(&prss, &gateway);

        match config.query_type {
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TestMultiply => {
                super::runner::TestMultiplyRunner
                    .run(ctx, config.field_type, input)
                    .await
            }
            QueryType::Ipa(ipa_query_config) => {
                IpaRunner(ipa_query_config)
                    .run(ctx, config.field_type, input)
                    .await
            }
        }
    })
}

#[cfg(all(test, not(feature = "shuttle"), feature = "in-memory-infra"))]
mod tests {
    use super::*;
    use crate::{ff::Fp31, secret_sharing::IntoShares};

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3)
            .map(Fp31::truncate_from)
            .collect::<Vec<_>>()
            .share();
        let expected = input.clone();
        let bytes = Box::new(input).into_bytes();
        assert_eq!(
            expected,
            AdditiveShare::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
        );
    }
}
