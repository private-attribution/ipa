#![cfg(all(feature = "web-app", feature = "cli"))]

use crate::{
    ff::{Field, GaloisField, Serializable},
    helpers::{query::QueryInput, BodyStream},
    ipa_test_input,
    net::MpcHelperClient,
    protocol::{attribution::input::MCAggregateCreditOutputRow, ipa::IPAInputRow, QueryId},
    secret_sharing::{replicated::semi_honest::AdditiveShare, IntoShares},
    test_fixture::{input::GenericReportTestInput, ipa::TestRawDataRecord, Reconstruct},
};
use futures_util::future::try_join_all;
use generic_array::GenericArray;
use rand::{distributions::Standard, prelude::Distribution};
use std::iter::zip;
use typenum::Unsigned;

/// Semi-honest IPA protocol.
/// Returns aggregated values per breakdown key represented as index in the returned vector
#[allow(clippy::missing_panics_doc)]
pub async fn playbook_ipa<F, MK, BK>(
    records: &[TestRawDataRecord],
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
) -> Vec<u32>
where
    F: Field + IntoShares<AdditiveShare<F>>,
    MK: GaloisField + IntoShares<AdditiveShare<MK>>,
    BK: GaloisField + IntoShares<AdditiveShare<BK>>,
    Standard: Distribution<F>,
    IPAInputRow<F, MK, BK>: Serializable,
    AdditiveShare<F>: Serializable,
{
    // prepare inputs
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
                (F, MK, BK)
            )
        })
        .collect::<Vec<_>>();

    let sz = <IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE;
    let mut buffers: [_; 3] = std::array::from_fn(|_| vec![0u8; inputs.len() * sz]);

    let shares: [Vec<IPAInputRow<_, _, _>>; 3] = inputs.share();
    zip(&mut buffers, shares).for_each(|(buf, shares)| {
        for (share, chunk) in zip(shares, buf.chunks_mut(sz)) {
            share.serialize(GenericArray::from_mut_slice(chunk));
        }
    });

    let inputs = buffers.map(BodyStream::from);

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

    let results: Vec<GenericReportTestInput<F, MK, BK>> = results
        .map(|bytes| {
            MCAggregateCreditOutputRow::<F, AdditiveShare<F>, BK>::from_byte_slice(&bytes)
                .collect::<Vec<_>>()
        })
        .reconstruct();

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
