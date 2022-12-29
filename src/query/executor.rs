use crate::ff::{Field, FieldType, Fp31};
use crate::helpers::messaging::Gateway;
use crate::helpers::negotiate_prss;
use crate::helpers::query::{IPAQueryConfig, QueryConfig, QueryType};
use crate::protocol::attribution::AggregateCreditOutputRow;
use crate::protocol::context::SemiHonestContext;
use crate::protocol::ipa::{ipa, IPAInputRow};
use crate::protocol::Step;
use crate::secret_sharing::Replicated;
use crate::task::JoinHandle;
use futures::Stream;
use futures_util::StreamExt;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
#[cfg(all(feature = "shuttle", test))]
use shuttle::future as tokio;

pub trait Result: Send {
    fn into_bytes(self: Box<Self>) -> Vec<u8>;
}

impl<F: Field> Result for Vec<Replicated<F>> {
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * Replicated::<F>::SIZE_IN_BYTES];
        for (i, share) in self.into_iter().enumerate() {
            share
                .serialize(&mut r[i * Replicated::<F>::SIZE_IN_BYTES..])
                .unwrap_or_else(|_| {
                    panic!(
                        "{share:?} cannot fit into {} byte slice",
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
                .unwrap_or_else(|_| {
                    panic!(
                        "{row:?} cannot fit into {} byte slice",
                        AggregateCreditOutputRow::<F>::SIZE_IN_BYTES
                    )
                });
        }

        r
    }
}

#[cfg(any(test, feature = "test-fixture"))]
async fn execute_test_multiply<F: Field, S: Stream<Item = Vec<u8>> + Send + Unpin>(
    ctx: SemiHonestContext<'_, F>,
    mut input: S,
) -> Vec<Replicated<F>> {
    use crate::protocol::basics::SecureMul;
    use crate::protocol::RecordId;

    let mut results = Vec::new();
    while let Some(v) = input.next().await {
        // multiply pairs
        let mut a = None;
        let mut record_id = 0_u32;
        for share in Replicated::<F>::from_byte_slice(&v) {
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

async fn execute_ipa<F: Field, S: Stream<Item = Vec<u8>> + Send + Unpin>(
    ctx: SemiHonestContext<'_, F>,
    query_config: IPAQueryConfig,
    mut input: S,
) -> Vec<AggregateCreditOutputRow<F>> {
    let mut inputs = Vec::new();
    while let Some(data) = input.next().await {
        inputs.extend(IPAInputRow::<F>::from_byte_slice(&data));
    }

    ipa(
        ctx,
        &inputs,
        query_config.num_bits,
        query_config.per_user_credit_cap,
        query_config.max_breakdown_key,
    )
    .await
    .unwrap()
}

pub fn start_query<S: Stream<Item = Vec<u8>> + Send + Unpin + 'static>(
    config: QueryConfig,
    gateway: Gateway,
    input: S,
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
                    #[cfg(any(test, feature = "test-fixture"))]
                    QueryType::TestMultiply => {
                        Box::new(execute_test_multiply(ctx, input).await) as Box<dyn Result>
                    }
                    QueryType::IPA(config) => {
                        Box::new(execute_ipa(ctx, config, input).await) as Box<dyn Result>
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
    use crate::protocol::ipa::test_cases;
    use crate::secret_sharing::IntoShares;
    use crate::test_fixture::{Reconstruct, TestWorld};
    use futures_util::future::join_all;
    use futures_util::stream;

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

            Box::new(stream::iter(std::iter::once(r)))
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
        let records = test_cases::Simple::<Fp31>::default()
            .share()
            // TODO: a trait would be useful here to convert IntoShares<T> to IntoShares<Vec<u8>>
            .map(|shares| {
                shares
                    .iter()
                    .flat_map(|share| {
                        let mut buf = [0u8; IPAInputRow::<Fp31>::SIZE_IN_BYTES];
                        share.serialize(&mut buf).unwrap();

                        buf
                    })
                    .collect::<Vec<_>>()
            });

        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();
        let results: [_; 3] = join_all(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IPAQueryConfig {
                num_bits: 20,
                per_user_credit_cap: 3,
                max_breakdown_key: 3,
            };
            execute_ipa(ctx, query_config, stream::iter(std::iter::once(shares)))
        }))
        .await
        .try_into()
        .unwrap();

        test_cases::Simple::<Fp31>::validate(&results);
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
