use crate::{
    error::Error,
    ff::Serializable,
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        ByteArrStream, Transport, TransportError, TransportImpl,
    },
    query::QueryProcessor,
    secret_sharing::IntoShares,
    sync::Arc,
    test_fixture::network::InMemoryNetwork,
    AppSetup, HelperApp,
};
use axum::extract::Query;
use futures_util::{future::try_join_all, FutureExt};
use generic_array::GenericArray;
use typenum::Unsigned;

pub trait IntoBuf {
    fn into_buf(self) -> Vec<u8>;
}

impl<I, S> IntoBuf for I
where
    I: IntoIterator<Item = S>,
    S: Serializable,
{
    fn into_buf(self) -> Vec<u8> {
        let this = self.into_iter();
        let (lb, ub) = this.size_hint();
        let cnt = ub.unwrap_or(lb);
        let item_size: usize = <S as Serializable>::Size::USIZE;

        let mut buf = vec![0u8; cnt * item_size];
        for (i, item) in this.enumerate() {
            let sl = &mut buf[i * item_size..(i + 1) * item_size];
            item.serialize(GenericArray::from_mut_slice(sl));
        }
        buf
    }
}

/// [`TestApp`] runs IPA queries end-to-end using [`InMemoryNetwork`]
/// It orchestrates the interaction between several components to drive queries to completion.
///
/// In contrast with [`TestWorld`] which can only run computations tied up to a single query, this
/// can potentially be used to run multiple queries in parallel.
///
/// [`InMemoryNetwork`]: crate::test_fixture::network::InMemoryNetwork
/// [`TestWorld`]: crate::test_fixture::TestWorld
pub struct TestApp {
    drivers: [HelperApp; 3],
    network: InMemoryNetwork,
}

fn unzip_tuple_array<T, U>(input: [(T, U); 3]) -> ([T; 3], [U; 3]) {
    let [v0, v1, v2] = input;
    ([v0.0, v1.0, v2.0], [v0.1, v1.1, v2.1])
}

impl TestApp {
    pub fn new() -> Self {
        let (setup, callbacks) =
            unzip_tuple_array([AppSetup::new(), AppSetup::new(), AppSetup::new()]);

        let network = InMemoryNetwork::new(callbacks);
        let drivers = network
            .transports()
            .iter()
            .zip(setup)
            .map(|(t, s)| s.connect(t.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .map_err(|_| "infallible")
            .unwrap();

        Self { drivers, network }
    }

    pub async fn execute_query<I, A>(
        &self,
        input: I,
        query_config: QueryConfig,
    ) -> Result<[Vec<u8>; 3], Error>
    where
        I: IntoShares<A>,
        A: IntoBuf,
    {
        let helpers_input = input.share().map(IntoBuf::into_buf);

        // helper 1 initiates the query
        let query_id = self.drivers[0].start_query(query_config).await?;

        // Send inputs and poll for completion
        let r = try_join_all(helpers_input.into_iter().enumerate().map(|(i, input)| {
            self.drivers[i].execute_query(QueryInput {
                query_id,
                input_stream: ByteArrStream::from(input),
            })
        }))
        .await?;

        Ok(<[_; 3]>::try_from(r).unwrap())
    }
}
