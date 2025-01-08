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

/// Secure multiplication. Each input must be a valid tuple of field values.
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::missing_panics_doc, clippy::disallowed_methods)]
pub async fn secure_mul<F>(
    // I couldn't make `share` work with `&[(F, F)]`
    input: Vec<(F, F)>,
    clients: &[IpaHttpClient<Helper>; 3],
    query_id: QueryId,
) -> Vec<F>
where
    F: Field + IntoShares<Replicated<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength,
{
    // prepare inputs
    let inputs = input.into_iter().share().map(|vec| {
        let r = vec
            .into_iter()
            .flat_map(|(a, b)| {
                let mut slice = vec![0u8; 2 * <Replicated<F> as Serializable>::Size::USIZE];
                a.serialize(GenericArray::from_mut_slice(
                    &mut slice[..<Replicated<F> as Serializable>::Size::USIZE],
                ));
                b.serialize(GenericArray::from_mut_slice(
                    &mut slice[<Replicated<F> as Serializable>::Size::USIZE..],
                ));

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

    // expect replicated shares to be sent back
    results
        .map(|bytes| {
            Replicated::<F>::from_byte_slice(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .reconstruct()
}
