use crate::{
    cli::playbook::InputSource,
    ff::{Field, FieldType},
    helpers::query::QueryInput,
    net::MpcHelperClient,
    protocol::{attribution::AggregateCreditOutputRow, ipa::IPAInputRow, QueryId},
    secret_sharing::IntoShares,
    test_fixture::IPAInputTestRow,
};
use futures_util::{future::try_join_all, stream};
use rand::{distributions::Standard, prelude::Distribution};
use std::fmt::Debug;

/// Semi-honest IPA protocol
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::unused_async)] // soon it will be used
#[allow(clippy::missing_panics_doc)]
pub async fn semi_honest<F>(
    input: InputSource,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    field_type: FieldType,
) -> [Vec<impl Send + Debug>; 3]
where
    F: Field,
    Standard: Distribution<F>,
{
    // prepare inputs
    let inputs = input
        .iter::<IPAInputTestRow>()
        .share()
        .map(|vec: Vec<IPAInputRow<F>>| {
            let r = vec
                .into_iter()
                .flat_map(|row| {
                    let mut slice = vec![0u8; IPAInputRow::<F>::SIZE_IN_BYTES];
                    row.serialize(&mut slice).unwrap();

                    slice
                })
                .collect::<Vec<_>>();

            Box::pin(stream::iter(std::iter::once(Ok(r))))
        });

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

    results.map(|bytes| AggregateCreditOutputRow::<F>::from_byte_slice(&bytes).collect::<Vec<_>>())
}
