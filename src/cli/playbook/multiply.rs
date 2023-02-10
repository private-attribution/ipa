use crate::{
    bits::Serializable,
    cli::playbook::InputSource,
    ff::Field,
    helpers::{query::QueryInput, transport::ByteArrStream},
    net::MpcHelperClient,
    protocol::QueryId,
    secret_sharing::{replicated::semi_honest::AdditiveShare as Replicated, IntoShares},
};
use futures_util::future::try_join_all;
use generic_array::{ArrayLength, GenericArray};
use std::fmt::Debug;
use std::ops::Add;
use typenum::Unsigned;

/// Secure multiplication. Each input must be a valid tuple of field values.
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::missing_panics_doc)]
pub async fn secure_mul<F>(
    input: InputSource,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
) -> [Vec<impl Send + Debug>; 3]
where
    F: Field + IntoShares<Replicated<F>>,
    <F as Serializable>::Size: Add<<F as Serializable>::Size>,
    <<F as Serializable>::Size as Add<<F as Serializable>::Size>>::Output: ArrayLength<u8>,
{
    // prepare inputs
    let inputs = input.iter::<(F, F)>().share().map(|vec| {
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

        ByteArrStream::from(r)
    });

    // send inputs
    try_join_all(
        inputs
            .into_iter()
            .zip(clients)
            .map(|(input_stream, client)| {
                client.query_input(QueryInput {
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
    results.map(|bytes| Replicated::<F>::from_byte_slice(&bytes).collect::<Vec<_>>())
}
