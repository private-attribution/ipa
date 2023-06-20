#![cfg(all(feature = "web-app", feature = "cli"))]

use crate::{
    ff::{Field, PrimeField, Serializable},
    helpers::{query::QueryInput, BodyStream},
    hpke::PublicKeyRegistry,
    ipa_test_input,
    net::MpcHelperClient,
    protocol::{
        attribution::input::MCAggregateCreditOutputRow, ipa::IPAInputRow, BreakdownKey, MatchKey,
        QueryId,
    },
    report::{KeyIdentifier, Report},
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    test_fixture::{input::GenericReportTestInput, ipa::TestRawDataRecord, Reconstruct},
};
use futures_util::future::try_join_all;
use generic_array::GenericArray;
use rand::{distributions::Standard, prelude::Distribution, rngs::StdRng};
use rand_core::SeedableRng;
use std::{iter::zip, time::Instant};
use typenum::Unsigned;

/// Semi-honest IPA protocol.
/// Returns aggregated values per breakdown key represented as index in the returned vector
#[allow(clippy::missing_panics_doc)]
pub async fn playbook_ipa<F, MK, BK, KR>(
    records: &[TestRawDataRecord],
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
    encryption: Option<(KeyIdentifier, [&KR; 3])>,
) -> Vec<u32>
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

    if let Some((key_id, key_registries)) = encryption {
        const ESTIMATED_AVERAGE_REPORT_SIZE: usize = 80; // TODO: confirm/adjust
        for buffer in &mut buffers {
            buffer.reserve(query_size * ESTIMATED_AVERAGE_REPORT_SIZE);
        }

        let mut rng = StdRng::from_entropy();
        let shares: [Vec<Report<_, _, _>>; 3] = records.to_owned().share();
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
        let sz = <IPAInputRow<F, MatchKey, BreakdownKey> as Serializable>::Size::USIZE;
        for buffer in &mut buffers {
            buffer.resize(query_size * sz, 0u8);
        }

        let inputs = records
            .iter()
            .map(|x| {
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
            })
            .collect::<Vec<_>>();
        let shares: [Vec<IPAInputRow<_, _, _>>; 3] = inputs.share();
        zip(&mut buffers, shares).for_each(|(buf, shares)| {
            for (share, chunk) in zip(shares, buf.chunks_mut(sz)) {
                share.serialize(GenericArray::from_mut_slice(chunk));
            }
        });
    }

    let inputs = buffers.map(BodyStream::from);
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

    // wait until helpers have processed the query and get the results from them
    let results: [_; 3] = try_join_all(clients.iter().map(|client| client.query_results(query_id)))
        .await
        .unwrap()
        .try_into()
        .unwrap();

    let results: Vec<GenericReportTestInput<F, MatchKey, BreakdownKey>> = results
        .map(|bytes| {
            MCAggregateCreditOutputRow::<F, AdditiveShare<F>, BreakdownKey>::from_byte_slice(&bytes)
                .collect::<Vec<_>>()
        })
        .reconstruct();
    tracing::info!(
        "Running IPA for {query_size:?} records took {t:?}",
        t = mpc_time.elapsed()
    );
    let mut breakdowns = Vec::new();
    for row in results {
        let breakdown_key = usize::try_from(row.breakdown_key.as_u128()).unwrap();
        // TODO: make the data type used consistent with `ipa_in_the_clear`
        // I think using u32 is wrong, we should move to u128
        let trigger_value = u32::try_from(row.trigger_value.as_u128()).unwrap();
        if breakdown_key >= breakdowns.len() {
            breakdowns.resize(breakdown_key + 1, 0);
            breakdowns[breakdown_key] += trigger_value
        }
    }

    breakdowns
}
