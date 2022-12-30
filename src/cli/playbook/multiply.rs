use crate::cli::playbook::InputSource;
use crate::ff::{Field, FieldType};
use crate::secret_sharing::{IntoShares, Replicated};
use std::fmt::Debug;

use crate::helpers::query::QueryInput;
use crate::helpers::transport::http::MpcHelperClient;
use crate::protocol::QueryId;
use futures_util::future::try_join_all;
use futures_util::stream;

/// Secure multiplication. Each input must be a valid tuple of field values.
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::unused_async)] // soon it will be used
#[allow(clippy::missing_panics_doc)]
pub async fn secure_mul<F>(
    input: InputSource,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    field_type: FieldType,
) -> [Vec<impl Send + Debug>; 3]
where
    F: Field + IntoShares<Replicated<F>>,
{
    // prepare inputs
    let inputs = input.iter::<(F, F)>().share().map(|vec| {
        let r = vec
            .into_iter()
            .flat_map(|(a, b)| {
                let mut slice = vec![0u8; 2 * Replicated::<F>::SIZE_IN_BYTES];
                a.serialize(&mut slice).unwrap();
                b.serialize(&mut slice[Replicated::<F>::SIZE_IN_BYTES..])
                    .unwrap();

                slice
            })
            .collect::<Vec<_>>();

        Box::pin(stream::iter(std::iter::once(Ok(r))))
    });

    // send inputs
    try_join_all(inputs.into_iter().zip(clients).map(|(input, client)| {
        client.query_input(QueryInput {
            query_id,
            field_type,
            input_stream: input,
        })
    }))
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
