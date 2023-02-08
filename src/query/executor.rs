use crate::secret_sharing::Arithmetic;
use crate::{
    bits::{BitArray, Serializable},
    ff::{Field, FieldType, Fp31},
    helpers::{
        messaging::{Gateway, TotalRecords},
        negotiate_prss,
        query::{IpaQueryConfig, QueryConfig, QueryType},
        transport::{AlignedByteArrStream, ByteArrStream},
    },
    protocol::{
        attribution::input::MCAggregateCreditOutputRow,
        context::SemiHonestContext,
        ipa::{ipa, IPAInputRow},
        BreakdownKey, MatchKey, Step,
    },
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
    task::JoinHandle,
};
use futures_util::StreamExt;
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

impl<F: Field> Result for Vec<Replicated<F>>
where
    Replicated<F>: Serializable,
{
    fn into_bytes(self: Box<Self>) -> Vec<u8> {
        let mut r = vec![0u8; self.len() * <Replicated<F> as Serializable>::Size::USIZE];
        for (i, share) in self.into_iter().enumerate() {
            share.serialize(GenericArray::from_mut_slice(
                &mut r[i * <Replicated<F> as Serializable>::Size::USIZE
                    ..(i + 1) * <Replicated<F> as Serializable>::Size::USIZE],
            ));
        }

        r
    }
}

impl<F: Field, T: Arithmetic<F>, BK: BitArray> Result for Vec<MCAggregateCreditOutputRow<F, T, BK>>
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

#[cfg(any(test, feature = "cli", feature = "test-fixture"))]
async fn execute_test_multiply<F: Field>(
    ctx: SemiHonestContext<'_, F>,
    mut input: AlignedByteArrStream,
) -> Vec<Replicated<F>>
where
    Replicated<F>: Serializable,
{
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

async fn execute_ipa<F: Field, MK: BitArray, BK: BitArray>(
    ctx: SemiHonestContext<'_, F>,
    query_config: IpaQueryConfig,
    mut input: AlignedByteArrStream,
) -> Vec<MCAggregateCreditOutputRow<F, Replicated<F>, BK>>
where
    IPAInputRow<F, MK, BK>: Serializable,
    Replicated<F>: Serializable,
{
    let mut input_vec = Vec::new();
    while let Some(data) = input.next().await {
        input_vec.extend(IPAInputRow::<F, MK, BK>::from_byte_slice(&data.unwrap()));
    }

    ipa(
        ctx,
        input_vec.as_slice(),
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
            FieldType::Fp31 => match config.query_type {
                #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
                QueryType::TestMultiply => {
                    let ctx = SemiHonestContext::<Fp31>::new_with_total_records(
                        &prss,
                        &gateway,
                        TotalRecords::Indeterminate,
                    );
                    let input = input.align(<Replicated<Fp31> as Serializable>::Size::USIZE);
                    Box::new(execute_test_multiply(ctx, input).await) as Box<dyn Result>
                }
                QueryType::IPA(config) => {
                    let ctx = SemiHonestContext::<Fp31>::new_with_total_records(
                        &prss,
                        &gateway,
                        // will be specified in downstream steps
                        TotalRecords::Unspecified,
                    );
                    let input = input.align(
                        <IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE,
                    );
                    Box::new(execute_ipa::<Fp31, MatchKey, BreakdownKey>(ctx, config, input).await)
                        as Box<dyn Result>
                }
            },
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
        ipa_test_input,
        protocol::context::Context,
        secret_sharing::IntoShares,
        test_fixture::{input::GenericReportTestInput, Reconstruct, TestWorld},
    };
    use futures_util::future::join_all;
    use generic_array::GenericArray;
    use typenum::Unsigned;

    #[tokio::test]
    async fn multiply() {
        let world = TestWorld::new().await;
        let contexts = world
            .contexts::<Fp31>()
            .map(|ctx| ctx.set_total_records(TotalRecords::Indeterminate));
        let a = [Fp31::from(4u128), Fp31::from(5u128)];
        let b = [Fp31::from(3u128), Fp31::from(6u128)];

        let helper_shares = (a, b).share().map(|(a, b)| {
            const SIZE: usize = <Replicated<Fp31> as Serializable>::Size::USIZE;
            let r = a
                .into_iter()
                .zip(b)
                .flat_map(|(a, b)| {
                    let mut slice = [0_u8; 2 * SIZE];
                    a.serialize(GenericArray::from_mut_slice(&mut slice[..SIZE]));
                    b.serialize(GenericArray::from_mut_slice(&mut slice[SIZE..]));

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
        const EXPECTED: &[[u128; 2]] = &[[0, 0], [1, 2], [2, 3]];

        let records: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> = ipa_test_input!(
            [
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 0, breakdown_key: 2, trigger_value: 0 },
                { match_key: 68362, is_trigger_report: 0, breakdown_key: 1, trigger_value: 0 },
                { match_key: 12345, is_trigger_report: 1, breakdown_key: 0, trigger_value: 5 },
                { match_key: 68362, is_trigger_report: 1, breakdown_key: 0, trigger_value: 2 },
            ];
            (Fp31, MatchKey, BreakdownKey)
        );
        let records = records
            .share()
            // TODO: a trait would be useful here to convert IntoShares<T> to IntoShares<Vec<u8>>
            .map(|shares| {
                shares
                    .into_iter()
                    .flat_map(|share: IPAInputRow<Fp31, MatchKey, BreakdownKey>| {
                        let mut buf = [0u8; <IPAInputRow<
                            Fp31,
                            MatchKey,
                            BreakdownKey,
                        > as Serializable>::Size::USIZE];
                        share.serialize(GenericArray::from_mut_slice(&mut buf));

                        buf
                    })
                    .collect::<Vec<_>>()
            });

        let world = TestWorld::new().await;
        let contexts = world.contexts::<Fp31>();
        let results: [_; 3] = join_all(records.into_iter().zip(contexts).map(|(shares, ctx)| {
            let query_config = IpaQueryConfig {
                num_multi_bits: 3,
                per_user_credit_cap: 3,
                max_breakdown_key: 3,
            };
            let input = ByteArrStream::from(shares)
                .align(<IPAInputRow<Fp31, MatchKey, BreakdownKey> as Serializable>::Size::USIZE);
            execute_ipa::<Fp31, MatchKey, BreakdownKey>(ctx, query_config, input)
        }))
        .await
        .try_into()
        .unwrap();

        let results: Vec<GenericReportTestInput<Fp31, MatchKey, BreakdownKey>> =
            results.reconstruct();
        for (i, expected) in EXPECTED.iter().enumerate() {
            assert_eq!(
                *expected,
                [
                    results[i].breakdown_key.as_u128(),
                    results[i].trigger_value.as_u128()
                ]
            );
        }
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
