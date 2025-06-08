use futures::StreamExt;

use crate::{
    error::Error,
    ff::{PrimeField, Serializable},
    helpers::{BodyStream, Gateway, RecordsStream, TotalRecords},
    protocol::{
        RecordId,
        basics::SecureMul,
        context::{Context, SemiHonestContext},
        prss::Endpoint as PrssEndpoint,
        step::ProtocolStep,
    },
    query::runner::QueryResult,
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

pub async fn execute_test_multiply<'a, F>(
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    input: BodyStream,
) -> QueryResult
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    let ctx = SemiHonestContext::new(prss, gateway).narrow(&ProtocolStep::Multiply);
    Ok(Box::new(
        execute_test_multiply_internal::<F>(ctx, input).await?,
    ))
}

pub async fn execute_test_multiply_internal<F>(
    ctx: SemiHonestContext<'_>,
    input_stream: BodyStream,
) -> Result<Vec<Replicated<F>>, Error>
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    let ctx = ctx.set_total_records(TotalRecords::Indeterminate);

    let mut input = Box::pin(RecordsStream::<Replicated<F>, _>::new(input_stream));
    let mut results = Vec::new();
    while let Some(v) = input.next().await {
        // multiply pairs
        let mut a = None;
        let mut record_id = 0_u32;
        for share in v.unwrap() {
            match a {
                None => a = Some(share),
                Some(a_v) => {
                    let result = a_v
                        .multiply(&share, ctx.clone(), RecordId::from(record_id))
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

    Ok(results)
}

#[cfg(all(test, unit_test))]
mod tests {
    use generic_array::GenericArray;
    use typenum::Unsigned;

    use super::*;
    use crate::{
        ff::{Fp31, U128Conversions},
        secret_sharing::IntoShares,
        test_fixture::{Reconstruct, TestWorld, join3v},
    };

    #[tokio::test]
    async fn multiply() {
        let world = TestWorld::default();
        let contexts = world.contexts();
        let a = [Fp31::truncate_from(4u128), Fp31::truncate_from(5u128)];
        let b = [Fp31::truncate_from(3u128), Fp31::truncate_from(6u128)];

        let helper_shares = (a.into_iter(), b.into_iter()).share().map(|(a, b)| {
            const SIZE: usize = <Replicated<Fp31> as Serializable>::Size::USIZE;
            a.into_iter()
                .zip(b)
                .flat_map(|(a, b)| {
                    let mut slice = [0_u8; 2 * SIZE];
                    a.serialize(GenericArray::from_mut_slice(&mut slice[..SIZE]));
                    b.serialize(GenericArray::from_mut_slice(&mut slice[SIZE..]));

                    slice
                })
                .collect::<Vec<_>>()
                .into()
        });

        let results = join3v(
            helper_shares
                .into_iter()
                .zip(contexts)
                .map(|(shares, context)| execute_test_multiply_internal::<Fp31>(context, shares)),
        )
        .await;

        let results = results.reconstruct();

        assert_eq!(
            vec![Fp31::truncate_from(12u128), Fp31::truncate_from(30u128)],
            results
        );
    }
}
