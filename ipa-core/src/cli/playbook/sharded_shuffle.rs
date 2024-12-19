use std::{
    cmp::{max, min},
    ops::Add,
    time::Duration,
};

use futures_util::future::try_join_all;
use generic_array::ArrayLength;

use crate::{
    ff::{boolean_array::BooleanArray, Serializable},
    helpers::{query::QueryInput, BodyStream},
    net::{Helper, IpaHttpClient},
    protocol::QueryId,
    query::QueryStatus,
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    test_fixture::Reconstruct,
};

/// Secure sharded shuffle protocol
///
/// ## Panics
/// If the input size is empty or contains only one row.
#[allow(clippy::disallowed_methods)] // allow try_join_all
pub async fn secure_shuffle<V>(
    inputs: Vec<V>,
    clients: &[[IpaHttpClient<Helper>; 3]],
    query_id: QueryId,
) -> Vec<V>
where
    V: IntoShares<AdditiveShare<V>>,
    <V as Serializable>::Size: Add<<V as Serializable>::Size, Output: ArrayLength>,
    V: BooleanArray,
{
    assert!(
        inputs.len() > 1,
        "Shuffle requires at least two rows to be shuffled"
    );
    let chunk_size = max(1, inputs.len() / clients.len());
    let _ = try_join_all(
        inputs
            .chunks(chunk_size)
            .zip(clients)
            .map(|(chunk, mpc_clients)| {
                let shared = chunk.iter().copied().share();
                try_join_all(mpc_clients.each_ref().iter().zip(shared).map(
                    |(mpc_client, input)| {
                        mpc_client.query_input(QueryInput::Inline {
                            query_id,
                            input_stream: BodyStream::from_serializable_iter(input),
                        })
                    },
                ))
            }),
    )
    .await
    .unwrap();
    let leader_clients = &clients[0];

    let mut delay = Duration::from_millis(125);
    loop {
        if try_join_all(
            leader_clients
                .iter()
                .map(|client| client.query_status(query_id)),
        )
        .await
        .unwrap()
        .into_iter()
        .all(|status| status == QueryStatus::Completed)
        {
            break;
        }

        tokio::time::sleep(delay).await;
        delay = min(Duration::from_secs(5), delay * 2);
    }

    let results: [_; 3] = try_join_all(
        leader_clients
            .iter()
            .map(|client| client.query_results(query_id)),
    )
    .await
    .unwrap()
    .try_into()
    .unwrap();
    let results: Vec<V> = results
        .map(|bytes| {
            AdditiveShare::<V>::from_byte_slice(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .reconstruct();

    results
}
