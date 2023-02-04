use crate::{
    bits::{BitArray, Serializable},
    cli::playbook::InputSource,
    ff::Field,
    helpers::{query::QueryInput, transport::ByteArrStream},
    net::MpcHelperClient,
    protocol::{attribution::input::MCAggregateCreditOutputRow, ipa::IPAInputRow, QueryId},
    secret_sharing::{
        replicated::semi_honest::{AdditiveShare as Replicated, XorShare as XorReplicated},
        IntoShares,
    },
    test_fixture::input::GenericReportTestInput,
};
use futures_util::future::try_join_all;
use generic_array::{ArrayLength, GenericArray};
use rand::{distributions::Standard, prelude::Distribution};
use std::fmt::Debug;
use std::ops::Add;
use typenum::Unsigned;

/// Semi-honest IPA protocol
/// `(a, b)` will produce `a` * `b`.
#[allow(clippy::missing_panics_doc)]
pub async fn semi_honest<F, MK, BK>(
    input: InputSource,
    clients: &[MpcHelperClient; 3],
    query_id: QueryId,
) -> [Vec<impl Send + Debug>; 3]
where
    F: Field + IntoShares<Replicated<F>>,
    MK: BitArray + IntoShares<XorReplicated<MK>>,
    BK: BitArray + IntoShares<XorReplicated<BK>>,
    Standard: Distribution<F>,
    XorReplicated<BK>: Serializable,
    XorReplicated<MK>: Serializable,
    Replicated<F>: Serializable,
    <XorReplicated<BK> as Serializable>::Size: Add<<Replicated<F> as Serializable>::Size>,
    <Replicated<F> as Serializable>::Size:
        Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >,
    <XorReplicated<MK> as Serializable>::Size: Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >,
    <<XorReplicated<MK> as Serializable>::Size as Add<
        <<Replicated<F> as Serializable>::Size as Add<
            <<XorReplicated<BK> as Serializable>::Size as Add<
                <Replicated<F> as Serializable>::Size,
            >>::Output,
        >>::Output,
    >>::Output: ArrayLength<u8>,
{
    // prepare inputs
    let inputs = input
        .iter::<GenericReportTestInput<F, MK, BK>>()
        .collect::<Vec<_>>()
        .share()
        .map(|vec: Vec<IPAInputRow<F, MK, BK>>| {
            let r = vec
                .into_iter()
                .flat_map(|row| {
                    let mut slice =
                        vec![0u8; <IPAInputRow<F, MK, BK> as Serializable>::Size::USIZE];
                    row.serialize(GenericArray::from_mut_slice(&mut slice));

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

    results.map(|bytes| {
        MCAggregateCreditOutputRow::<F, BK>::from_byte_slice(&bytes).collect::<Vec<_>>()
    })
}
