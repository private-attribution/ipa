#![cfg(feature = "web-app")]

use std::ops::Add;

use futures::future::try_join_all;
use generic_array::{ArrayLength, GenericArray};
use typenum::Unsigned;

use crate::{
    ff::{Field, Serializable},
    helpers::{query::QueryInput, BodyStream},
    net::{Helper, IpaHttpClient},
    protocol::QueryId,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
    test_fixture::Reconstruct,
};

/// Secure addition.
#[allow(clippy::missing_panics_doc, clippy::disallowed_methods)]
pub async fn secure_add<F>(
    input: impl Iterator<Item = F>,
    clients: &[IpaHttpClient<Helper>; 3],
    query_id: QueryId,
) -> F
where
    F: Field + IntoShares<Replicated<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    // prepare inputs
    let inputs = input.share().map(|vec| {
        let r = vec
            .into_iter()
            .flat_map(|item| {
                let mut slice = vec![0u8; <Replicated<F> as Serializable>::Size::USIZE];
                item.serialize(GenericArray::from_mut_slice(&mut slice));
                slice
            })
            .collect::<Vec<_>>();

        BodyStream::from(r)
    });

    // send inputs
    try_join_all(
        inputs
            .into_iter()
            .zip(clients)
            .map(|(input_stream, client)| {
                client.query_input(QueryInput::Inline {
                    query_id,
                    input_stream,
                })
            }),
    )
    .await
    .unwrap();

    // wait until helpers have processed the query and get the results from them
    let results: [_; 3] = try_join_all(clients.iter().map(|client| client.query_results(query_id)))
        .await
        .unwrap()
        .try_into()
        .unwrap();

    results
        .map(|bytes| Replicated::<F>::deserialize(GenericArray::from_slice(&bytes)).unwrap())
        .reconstruct()
}
