use crate::{
    bits::{BitArray, Serializable},
    cli::playbook::InputSource,
    ff::Field,
    helpers::{query::QueryInput, transport::ByteArrStream},
    net::MpcHelperClient,
    protocol::{attribution::AggregateCreditOutputRow, ipa::IPAInputRow, QueryId},
    secret_sharing::IntoShares,
    test_fixture::IPAInputTestRow,
};
use futures_util::future::try_join_all;
use rand::{distributions::Standard, prelude::Distribution};
use std::fmt::Debug;

/// Semi-honest IPA protocol
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::missing_panics_doc)]
pub async fn semi_honest<F, B>(
    input: InputSource,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
) -> [Vec<impl Send + Debug>; 3]
where
    F: Field,
    B: BitArray,
    Standard: Distribution<F> + Distribution<B>,
{
    // prepare inputs
    let inputs = input
        .iter::<IPAInputTestRow>()
        .share()
        .map(|vec: Vec<IPAInputRow<F, B>>| {
            let r = vec
                .into_iter()
                .flat_map(|row| {
                    let mut slice = vec![0u8; IPAInputRow::<F, B>::SIZE_IN_BYTES];
                    row.serialize(&mut slice).unwrap();

                    slice
                })
                .collect::<Vec<_>>();

            ByteArrStream::from(r)
        });

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

    results.map(|bytes| AggregateCreditOutputRow::<F>::from_byte_slice(&bytes).collect::<Vec<_>>())
}
