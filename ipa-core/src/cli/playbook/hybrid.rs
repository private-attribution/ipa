#![cfg(all(feature = "web-app", feature = "cli"))]
use std::{
    cmp::min,
    iter::zip,
    time::{Duration, Instant},
};

use futures_util::future::try_join_all;
use serde::{Deserialize, Serialize};
use tokio::time::sleep;

use crate::{
    ff::{Serializable, U128Conversions},
    helpers::query::{HybridQueryParams, QueryInput, QuerySize},
    net::{Helper, IpaHttpClient},
    query::QueryStatus,
    secret_sharing::{replicated::semi_honest::AdditiveShare, SharedValue},
    test_fixture::Reconstruct,
};

/// # Panics
/// if results are invalid
#[allow(clippy::disallowed_methods)] // allow try_join_all
pub async fn run_hybrid_query_and_validate<HV>(
    inputs: Vec<[QueryInput; 3]>,
    query_size: usize,
    clients: Vec<[IpaHttpClient<Helper>; 3]>,
    query_config: HybridQueryParams,
    set_fixed_polling_ms: Option<u64>,
) -> HybridQueryResult
where
    HV: SharedValue + U128Conversions,
    AdditiveShare<HV>: Serializable,
{
    let query_id = inputs
        .first()
        .map(|v| v[0].query_id())
        .expect("At least one shard must be used to run a Hybrid query");
    let mpc_time = Instant::now();
    assert_eq!(clients.len(), inputs.len());
    // submit inputs to each shard
    let _ = try_join_all(zip(clients.iter(), inputs.into_iter()).map(
        |(shard_clients, shard_inputs)| {
            try_join_all(
                shard_clients
                    .iter()
                    .zip(shard_inputs.into_iter())
                    .map(|(client, input)| client.query_input(input)),
            )
        },
    ))
    .await
    .unwrap();

    let leader_clients = &clients[0];

    let (exponential_backoff, mut delay) = match set_fixed_polling_ms {
        Some(specified_delay) => (false, Duration::from_millis(specified_delay)),
        None => (true, Duration::from_millis(125)),
    };

    loop {
        if try_join_all(
            leader_clients
                .each_ref()
                .map(|client| client.query_status(query_id)),
        )
        .await
        .unwrap()
        .into_iter()
        .all(|status| status == QueryStatus::Completed)
        {
            break;
        }

        sleep(delay).await;
        if exponential_backoff {
            delay = min(Duration::from_secs(5), delay * 2);
        }
        // TODO: Add a timeout of some sort. Possibly, add some sort of progress indicator to
        // the status API so we can check whether the query is making progress.
    }

    // wait until helpers have processed the query and get the results from them
    let results: [_; 3] = try_join_all(
        leader_clients
            .iter()
            .map(|client| client.query_results(query_id)),
    )
    .await
    .unwrap()
    .try_into()
    .unwrap();

    let results: Vec<HV> = results
        .map(|bytes| {
            AdditiveShare::<HV>::from_byte_slice(&bytes)
                .collect::<Result<Vec<_>, _>>()
                .unwrap()
        })
        .reconstruct();

    let lat = mpc_time.elapsed();

    tracing::info!("Running IPA for {query_size:?} records took {t:?}", t = lat);
    let mut breakdowns = vec![0; usize::try_from(query_config.max_breakdown_key).unwrap()];
    for (breakdown_key, trigger_value) in results.into_iter().enumerate() {
        // TODO: make the data type used consistent with `ipa_in_the_clear`
        // I think using u32 is wrong, we should move to u128
        if query_config.with_dp == 0 {
            // otherwise if DP is added trigger_values will not be zero due to noise
            assert!(
                breakdown_key < query_config.max_breakdown_key.try_into().unwrap()
                    || trigger_value == HV::ZERO,
                "trigger values were attributed to buckets more than max breakdown key"
            );
        }

        if breakdown_key < query_config.max_breakdown_key.try_into().unwrap() {
            breakdowns[breakdown_key] += u32::try_from(trigger_value.as_u128()).unwrap();
        }
    }

    HybridQueryResult {
        input_size: QuerySize::try_from(query_size).unwrap(),
        config: query_config,
        latency: lat,
        breakdowns,
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HybridQueryResult {
    pub input_size: QuerySize,
    pub config: HybridQueryParams,
    #[serde(
        serialize_with = "crate::serde::duration::to_secs",
        deserialize_with = "crate::serde::duration::from_secs"
    )]
    pub latency: Duration,
    pub breakdowns: Vec<u32>,
}
