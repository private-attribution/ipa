use std::pin::pin;

use futures::StreamExt;

use crate::{
    error::Error,
    ff::{PrimeField, Serializable},
    helpers::{BodyStream, Gateway, SingleRecordStream},
    protocol::{
        context::{Context, SemiHonestContext},
        prss::Endpoint as PrssEndpoint,
        step::ProtocolStep,
    },
    query::runner::QueryResult,
    secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
};

#[tracing::instrument("test-add", skip_all)]
pub async fn add<'a, F>(
    prss: &'a PrssEndpoint,
    gateway: &'a Gateway,
    input: BodyStream,
) -> QueryResult
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    let ctx = SemiHonestContext::new(prss, gateway).narrow(&ProtocolStep::Add);
    Ok(Box::new(add_internal::<F>(ctx, input).await?))
}

pub async fn add_internal<F>(
    _ctx: SemiHonestContext<'_>,
    input_stream: BodyStream,
) -> Result<Vec<Replicated<F>>, Error>
where
    F: PrimeField,
    Replicated<F>: Serializable,
{
    let mut input_stream = pin!(SingleRecordStream::<Replicated<F>, _>::new(input_stream));
    let mut sum = Replicated::ZERO;
    while let Some(Ok(record)) = input_stream.next().await {
        sum += record;
    }

    Ok(vec![sum])
}

#[cfg(all(test, unit_test))]
mod tests {
    use generic_array::GenericArray;
    use typenum::Unsigned;

    use super::*;
    use crate::{
        ff::{Fp31, U128Conversions},
        secret_sharing::IntoShares,
        test_fixture::{join3v, Reconstruct, TestWorld},
    };

    #[tokio::test]
    async fn add() {
        let world = TestWorld::default();
        let contexts = world.contexts();
        let input = vec![
            Fp31::truncate_from(4_u128),
            Fp31::truncate_from(5_u128),
            Fp31::truncate_from(6_u128),
            Fp31::truncate_from(7_u128),
            Fp31::truncate_from(8_u128),
            Fp31::truncate_from(9_u128),
        ];

        let shares: [Vec<Replicated<Fp31>>; 3] = input.into_iter().share();

        let helper_shares = shares.map(|shares| {
            const SIZE: usize = <Replicated<Fp31> as Serializable>::Size::USIZE;
            shares
                .into_iter()
                .flat_map(|share| {
                    let mut slice = [0_u8; SIZE];
                    share.serialize(GenericArray::from_mut_slice(&mut slice));
                    slice
                })
                .collect::<Vec<_>>()
                .into()
        });

        let results = join3v(
            helper_shares
                .into_iter()
                .zip(contexts)
                .map(|(shares, context)| add_internal::<Fp31>(context, shares)),
        )
        .await;

        let results = results.reconstruct();

        assert_eq!(vec![Fp31::truncate_from(8_u128)], results);
    }
}
