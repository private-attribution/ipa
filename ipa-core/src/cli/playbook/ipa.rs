#![cfg(all(feature = "web-app", feature = "cli"))]
use std::{
    cmp::min,
    iter::zip,
    time::{Duration, Instant},
};

use futures_util::future::try_join_all;
use generic_array::GenericArray;
use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng};
use rand_core::SeedableRng;
use tokio::time::sleep;
use typenum::Unsigned;

use crate::{
    cli::IpaQueryResult,
    ff::{PrimeField, Serializable},
    helpers::{
        query::{IpaQueryConfig, QueryInput, QuerySize},
        BodyStream,
    },
    hpke::PublicKeyRegistry,
    ipa_test_input,
    net::MpcHelperClient,
    protocol::{ipa::IPAInputRow, BreakdownKey, MatchKey, QueryId, Timestamp, TriggerValue},
    query::QueryStatus,
    report::{KeyIdentifier, OprfReport, Report},
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    test_fixture::{input::GenericReportTestInput, ipa::TestRawDataRecord, Reconstruct},
};

/// Semi-honest IPA protocol.
/// Returns aggregated values per breakdown key represented as index in the returned vector
#[allow(clippy::missing_panics_doc)]
pub async fn playbook_ipa<F, MK, BK, KR>(
    records: &[TestRawDataRecord],
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    query_config: IpaQueryConfig,
    encryption: Option<(KeyIdentifier, [&KR; 3])>,
) -> IpaQueryResult
where
    F: PrimeField + IntoShares<AdditiveShare<F>>,
    Standard: Distribution<F>,
    IPAInputRow<F, MatchKey, BreakdownKey>: Serializable,
    TestRawDataRecord: IntoShares<Report<F, MatchKey, BreakdownKey>>,
    AdditiveShare<F>: Serializable,
    KR: PublicKeyRegistry,
{
    let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());
    let query_size = records.len();

    if !query_config.plaintext_match_keys {
        if let Some((key_id, key_registries)) = encryption {
            const ESTIMATED_AVERAGE_REPORT_SIZE: usize = 80; // TODO: confirm/adjust
            for buffer in &mut buffers {
                buffer.reserve(query_size * ESTIMATED_AVERAGE_REPORT_SIZE);
            }

            let mut rng = StdRng::from_entropy();
            let shares: [Vec<Report<_, _, _>>; 3] = records.iter().cloned().share();
            zip(&mut buffers, shares).zip(key_registries).for_each(
                |((buf, shares), key_registry)| {
                    for share in shares {
                        share
                            .delimited_encrypt_to(key_id, key_registry, &mut rng, buf)
                            .unwrap();
                    }
                },
            );
        } else {
            panic!("match key encryption was requested, but one or more helpers is missing a public key")
        }
    } else {
        let sz = <IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE;
        for buffer in &mut buffers {
            buffer.resize(query_size * sz, 0u8);
        }

        let inputs = records.iter().map(|x| {
            ipa_test_input!(
                {
                    timestamp: x.timestamp,
                    match_key: x.user_id,
                    is_trigger_report: x.is_trigger_report,
                    breakdown_key: x.breakdown_key,
                    trigger_value: x.trigger_value,
                };
                (F, MatchKey, BreakdownKey)
            )
        });
        let shares: [Vec<IPAInputRow<_, _, _>>; 3] = inputs.share();
        zip(&mut buffers, shares).for_each(|(buf, shares)| {
            for (share, chunk) in zip(shares, buf.chunks_mut(sz)) {
                share.serialize(GenericArray::from_mut_slice(chunk));
            }
        });
    }

    let inputs = buffers.map(BodyStream::from);
    tracing::info!("Starting query after finishing encryption");

    run_query_and_validate::<F>(inputs, query_size, clients, query_id, query_config).await
}

pub async fn playbook_oprf_ipa<F>(
    mut records: Vec<TestRawDataRecord>,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    query_config: IpaQueryConfig,
) -> IpaQueryResult
where
    F: PrimeField,
    AdditiveShare<F>: Serializable,
{
    let mut buffers: [_; 3] = std::array::from_fn(|_| Vec::new());
    let query_size = records.len();

    let sz = <OprfReport<BreakdownKey, TriggerValue, Timestamp> as Serializable>::Size::USIZE;
    for buffer in &mut buffers {
        buffer.resize(query_size * sz, 0u8);
    }

    //TODO(richaj) This manual sorting will be removed once we have the PRF sharding in place.
    //This does a stable sort. It also expects the inputs to be sorted by timestamp
    records.sort_by(|a, b| b.user_id.cmp(&a.user_id));

    let shares: [Vec<OprfReport<BreakdownKey, TriggerValue, Timestamp>>; 3] =
        records.iter().cloned().share();
    zip(&mut buffers, shares).for_each(|(buf, shares)| {
        for (share, chunk) in zip(shares, buf.chunks_mut(sz)) {
            share.serialize(GenericArray::from_mut_slice(chunk));
        }
    });

    let inputs = buffers.map(BodyStream::from);
    tracing::info!("Starting query for OPRF");

    run_query_and_validate::<F>(inputs, query_size, clients, query_id, query_config).await
}

pub async fn run_query_and_validate<F>(
    inputs: [BodyStream; 3],
    query_size: usize,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    query_config: IpaQueryConfig,
) -> IpaQueryResult
where
    F: PrimeField,
    AdditiveShare<F>: Serializable,
{
    let mpc_time = Instant::now();
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

    let results: Vec<F> = results
        .map(|bytes| AdditiveShare::<F>::from_byte_slice(&bytes).collect::<Vec<_>>())
        .reconstruct();

    let lat = mpc_time.elapsed();

    tracing::info!("Running IPA for {query_size:?} records took {t:?}", t = lat);
    let mut breakdowns = vec![0; usize::try_from(query_config.max_breakdown_key).unwrap()];
    for (breakdown_key, trigger_value) in results.into_iter().enumerate() {
        // TODO: make the data type used consistent with `ipa_in_the_clear`
        // I think using u32 is wrong, we should move to u128
        assert!(
            breakdown_key < query_config.max_breakdown_key.try_into().unwrap()
                || trigger_value == F::ZERO,
            "trigger values were attributed to buckets more than max breakdown key"
        );
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
