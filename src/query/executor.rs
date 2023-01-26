use crate::{
    bits::{BitArray, Serializable},
    ff::{Field, FieldType, Fp31},
    helpers::{
        messaging::Gateway,
        negotiate_prss,
        query::{IPAQueryConfig, QueryConfig, QueryType},
        transport::{AlignedByteArrStream, ByteArrStream},
    },
    protocol::{
        attribution::AggregateCreditOutputRow,
        context::SemiHonestContext,
        ipa::{ipa, IPAInputRow},
        MatchKey, Step,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
    task::JoinHandle,
};
use futures_util::StreamExt;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;
use std::fmt::Debug;

pub trait Result: Send + Debug {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<F: Field> Result for Vec<Replicated<F>> {
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * Replicated::<F>::SIZE_IN_BYTES];
        for (i, share) in self.into_iter().enumerate() {
            share
                .serialize(&mut r[i * Replicated::<F>::SIZE_IN_BYTES..])
                .unwrap_or_else(|err| {
                    panic!(
                        "cannot fit into {} byte slice: {err}",
                        Replicated::<F>::SIZE_IN_BYTES
                    )
                });
        }

        r
    }
}

impl<F: Field> Result for Vec<AggregateCreditOutputRow<F>> {
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * AggregateCreditOutputRow::<F>::SIZE_IN_BYTES];

        for (i, row) in self.into_iter().enumerate() {
            row.serialize(&mut r[i * AggregateCreditOutputRow::<F>::SIZE_IN_BYTES..])
                .unwrap_or_else(|err| {
                    panic!(
                        "cannot fit into {} byte slice: {err}",
                        AggregateCreditOutputRow::<F>::SIZE_IN_BYTES
                    )
                });
        }

        r
    }
}

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
async fn execute_test_multiply<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    mut input: AlignedByteArrStream,
) -> Vec<Replicated<F>> {
    use crate::protocol::basics::SecureMul;
    use crate::protocol::RecordId;

    let mut results = Vec::new();
    while let Some(v) = input.next().await {
        // multiply pairs
        let mut a = None;
        let mut record_id = 0_u32;
        for share in Replicated::<F>::from_byte_slice(&v.unwrap()) {
            match a {
                None => a = Some(share),
                Some(a_v) => {
                    let result = ctx
                        .clone()
                        .multiply(RecordId::from(record_id), &a_v, &share)
                        .await
                        .unwrap();
                    results.push(result);
                    record_id += 1;
                    a = None;
                }
            }
        }

        assert!(a.is_none());
    }

    results
}

async fn execute_ipa<F: Field, B: BitArray>(
    ctx: SemiHonestContext<'_, F>,
    query_config: IPAQueryConfig,
    mut input: AlignedByteArrStream,
) -> Vec<AggregateCreditOutputRow<F>> {
    let mut inputs = Vec::new();
    while let Some(data) = input.next().await {
        inputs.extend(IPAInputRow::<F, B>::from_byte_slice(&data.unwrap()));
    }

    ipa(
        ctx,
        &inputs,
        query_config.per_user_credit_cap,
        query_config.max_breakdown_key,
        query_config.num_multi_bits,
    )
    .await
    .unwrap()
}

pub fn start_query(
    config: QueryConfig,
    gateway: Gateway,
    input: ByteArrStream,
) -> JoinHandle<Box<dyn Result>> {
    tokio::spawn(async move {
        // TODO: make it a generic argument for this function
        let mut rng = StdRng::from_entropy();
        // Negotiate PRSS first
        let step = Step::default().narrow(&config.query_type);
        let prss = negotiate_prss(&gateway, &step, &mut rng).await.unwrap();

        match config.field_type {
            FieldType::Fp31 => {
                let ctx = SemiHonestContext::<Fp31>::new(&prss, &gateway);
                match config.query_type {
                    #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                    QueryType::TestMultiply => {
                        let input = input.align(Replicated::<Fp31>::SIZE_IN_BYTES);
                        Box::new(execute_test_multiply(ctx, input).await) as Box<dyn Result>
                    }
                    QueryType::IPA(config) => {
                        let input = input.align(IPAInputRow::<Fp31, MatchKey>::SIZE_IN_BYTES);
                        Box::new(execute_ipa::<Fp31, MatchKey>(ctx, config, input).await)
                            as Box<dyn Result>
                    }
                }
            }
            FieldType::Fp32BitPrime => {
                todo!()
            }
        }
    })
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        protocol::ipa::test_cases,
        secret_sharing::IntoShares,
        test_fixture::{Reconstruct, TestWorld},
    };
    use futures_util::future::join_all;

    #[tokio::test]
    async fn multiply() {
        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();
        let a = [Fp31::from(4u128), Fp31::from(5u128)];
        let b = [Fp31::from(3u128), Fp31::from(6u128)];

        let helper_shares = (a, b).share().map(|(a, b)| {
            const SIZE: usize = Replicated::<Fp31>::SIZE_IN_BYTES;
            let r = a
                .into_iter()
                .zip(b)
                .flat_map(|(a, b)| {
                    let mut slice = [0_u8; 2 * SIZE];
                    a.serialize(&mut slice).unwrap();
                    b.serialize(&mut slice[SIZE..]).unwrap();

                    slice
                })
                .collect::<Vec<_>>();

            ByteArrStream::from(r).align(SIZE)
        });

        let results: [_; 3] = join_all(
            helper_shares
                .into_iter()
                .zip(contexts)
                .map(|(shares, context)| execute_test_multiply(context, shares)),
        )
        .await
        .try_into()
        .unwrap();

        let results = results.reconstruct();

        assert_eq!(vec![Fp31::from(12u128), Fp31::from(30u128)], results);
    }

    #[tokio::test]
    async fn ipa() {
        let records = test_cases::Simple::<Fp31, MatchKey>::default()
            .share()
            // TODO: a trait would be useful here to convert IntoShares<T> to IntoShares<Vec<u8>>
            .map(|shares| {
                shares
                    .into_iter()
                    .flat_map(|share| {
                        let mut buf = [0u8; IPAInputRow::<Fp31, MatchKey>::SIZE_IN_BYTES];
                        share.serialize(&mut buf).unwrap();

                        buf
                    })
                    .collect::<Vec<_>>()
            });

        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();
        let results: [_; 3] = join_all(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IPAQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares.as_slice())
                .align(IPAInputRow::<Fp31, MatchKey>::SIZE_IN_BYTES);
            execute_ipa::<Fp31, MatchKey>(ctx, query_config, input)
        }))
        .await
        .try_into()
        .unwrap();

        test_cases::Simple::<Fp31, MatchKey>::validate(&results);
    }

    #[test]
    fn serialize_result() {
        let [input, ..] = (0u128..=3).map(Fp31::from).collect::<Vec<_>>().share();
        let expected = input.clone();
        let bytes = Box::new(input).into_bytes();
        assert_eq!(
            expected,
            Replicated::<Fp31>::from_byte_slice(&bytes).collect::<Vec<_>>()
        );
    }
}
