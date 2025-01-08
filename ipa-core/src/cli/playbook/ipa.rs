#![cfg(all(feature = "web-app", feature = "cli"))]
use std::{
    cmp::min,
    iter::zip,
    time::{Duration, Instant},
};

use futures_util::future::try_join_all;
use generic_array::GenericArray;
use rand::rngs::StdRng;
use rand_core::SeedableRng;
use tokio::time::sleep;
use typenum::Unsigned;

use crate::{
    cli::{
        playbook::{BreakdownKey, Timestamp, TriggerValue},
        IpaQueryResult,
    },
    ff::{Serializable, U128Conversions},
    helpers::{
        query::{IpaQueryConfig, QueryInput, QuerySize},
        BodyStream,
    },
    hpke::PublicKeyRegistry,
    net::{Helper, IpaHttpClient},
    protocol::{ipa_prf::OPRFIPAInputRow, QueryId},
    query::QueryStatus,
    report::{KeyIdentifier, OprfReport},
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares, SharedValue},
    test_fixture::{ipa::TestRawDataRecord, Reconstruct},
};

/// Executes the IPA v3 protocol.
///
/// ## Panics
/// If report encryption fails
pub async fn playbook_oprf_ipa<HV, KR>(
    records: Vec<TestRawDataRecord>,
    clients: &[IpaHttpClient<Helper>; 3],
    query_id: QueryId,
    query_config: IpaQueryConfig,
    encryption: Option<(KeyIdentifier, [&KR; 3])>,
) -> IpaQueryResult
where
    HV: SharedValue + U128Conversions,
    AdditiveShare<HV>: Serializable,
    KR: PublicKeyRegistry,
{
    let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());
    let query_size = records.len();

    if query_config.plaintext_match_keys {
        let sz =
            <OPRFIPAInputRow<BreakdownKey, TriggerValue, Timestamp> as Serializable>::Size::USIZE;
        for buffer in &mut buffers {
            buffer.resize(query_size * sz, 0u8);
        }

        let shares: [Vec<OPRFIPAInputRow<BreakdownKey, TriggerValue, Timestamp>>; 3] =
            records.iter().cloned().share();

        zip(&mut buffers, shares).for_each(|(buf, shares)| {
            for (share, chunk) in zip(shares, buf.chunks_mut(sz)) {
                share.serialize(GenericArray::from_mut_slice(chunk));
            }
        });
    } else if let Some((key_id, key_registries)) = encryption {
        const ESTIMATED_AVERAGE_REPORT_SIZE: usize = 80; // TODO: confirm/adjust
        for buffer in &mut buffers {
            buffer.reserve(query_size * ESTIMATED_AVERAGE_REPORT_SIZE);
        }

        let mut rng = StdRng::from_entropy();
        let shares: [Vec<OprfReport<BreakdownKey, TriggerValue, Timestamp>>; 3] =
            records.iter().cloned().share();
        zip(&mut buffers, shares)
            .zip(key_registries)
            .for_each(|((buf, shares), key_registry)| {
                for share in shares {
                    share
                        .delimited_encrypt_to(key_id, key_registry, &mut rng, buf)
                        .unwrap();
                }
            });
    } else {
        panic!(
            "match key encryption was requested, but one or more helpers is missing a public key"
        )
    }

    let inputs = buffers.map(BodyStream::from);
    tracing::info!("Starting query for OPRF");

    run_query_and_validate::<HV>(inputs, query_size, clients, query_id, query_config).await
}

/// # Panics
/// if results are invalid
#[allow(clippy::disallowed_methods)] // allow try_join_all
pub async fn run_query_and_validate<HV>(
    inputs: [BodyStream; 3],
    query_size: usize,
    clients: &[IpaHttpClient<Helper>; 3],
    query_id: QueryId,
    query_config: IpaQueryConfig,
) -> IpaQueryResult
where
    HV: SharedValue + U128Conversions,
    AdditiveShare<HV>: Serializable,
{
    let mpc_time = Instant::now();
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

    let mut delay = Duration::from_millis(125);
    loop {
        if try_join_all(clients.iter().map(|client| client.query_status(query_id)))
            .await
            .unwrap()
            .into_iter()
            .all(|status| status == QueryStatus::Completed)
        {
            break;
        }

        sleep(delay).await;
        delay = min(Duration::from_secs(5), delay * 2);
        // TODO: Add a timeout of some sort. Possibly, add some sort of progress indicator to
        // the status API so we can check whether the query is making progress.
    }

    // wait until helpers have processed the query and get the results from them
    let results: [_; 3] = try_join_all(clients.iter().map(|client| client.query_results(query_id)))
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

    IpaQueryResult {
        input_size: QuerySize::try_from(query_size).unwrap(),
        config: query_config,
        latency: lat,
        breakdowns,
    }
}
