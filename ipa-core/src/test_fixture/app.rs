use std::{array, iter::zip};

use generic_array::GenericArray;
use typenum::Unsigned;

use crate::{
    app::AppConfig,
    ff::Serializable,
    helpers::{
        query::{QueryConfig, QueryInput},
        ApiError, InMemoryMpcNetwork, InMemoryShardNetwork, Transport,
    },
    protocol::QueryId,
    query::QueryStatus,
    secret_sharing::IntoShares,
    test_fixture::try_join3_array,
    utils::array::zip3,
    AppSetup, HelperApp,
};

pub trait IntoBuf {
    fn into_buf(self) -> Vec<u8>;
}

impl<I, S> IntoBuf for I
where
    I: IntoIterator<Item = S>,
    I::IntoIter: ExactSizeIterator,
    S: Serializable,
{
    fn into_buf(self) -> Vec<u8> {
        let this = self.into_iter();
        let item_size: usize = <S as Serializable>::Size::USIZE;

        let mut buf = vec![0u8; this.len() * item_size];
        for (item, chunk) in zip(this, buf.chunks_mut(item_size)) {
            item.serialize(GenericArray::from_mut_slice(chunk));
        }
        buf
    }
}

/// [`TestApp`] runs IPA queries end-to-end using [`InMemoryNetwork`]
/// It orchestrates the interaction between several components to drive queries to completion.
///
/// In contrast with [`TestWorld`] which can only run computations tied up to a single query, this
/// can potentially be used to run multiple queries in parallel. The guidance is to use `[TestWorld`]
/// for unit tests and [`TestApp`] for integration/end-to-end tests.
///
/// [`InMemoryNetwork`]: crate::test_fixture::network::InMemoryNetwork
/// [`TestWorld`]: crate::test_fixture::TestWorld
pub struct TestApp {
    drivers: [HelperApp; 3],
    mpc_network: InMemoryMpcNetwork,
    shard_network: InMemoryShardNetwork,
}

fn unzip_tuple_array<T, U, V>(input: [(T, U, V); 3]) -> ([T; 3], [U; 3], [V; 3]) {
    let [v0, v1, v2] = input;
    ([v0.0, v1.0, v2.0], [v0.1, v1.1, v2.1], [v0.2, v1.2, v2.2])
}

impl Default for TestApp {
    fn default() -> Self {
        let (setup, handlers, _shard_handlers) =
            unzip_tuple_array(array::from_fn(|_| AppSetup::new(AppConfig::default())));

        let mpc_network = InMemoryMpcNetwork::new(handlers.map(Some));
        let shard_network = InMemoryShardNetwork::with_shards(1);
        let drivers = zip3(mpc_network.transports().each_ref(), setup)
            .map(|(t, s)| s.connect(Clone::clone(t), shard_network.transport(t.identity(), 0)));

        Self {
            drivers,
            mpc_network,
            shard_network,
        }
    }
}

impl TestApp {
    /// Initiates a new query on all helpers and drives it to completion.
    ///
    /// ## Errors
    /// Returns an error if it can't start a query or send query input.
    #[allow(clippy::missing_panics_doc)]

    pub async fn start_query<I, A>(
        &self,
        input: I,
        query_config: QueryConfig,
    ) -> Result<QueryId, ApiError>
    where
        I: IntoShares<A>,
        A: IntoBuf,
    {
        let helpers_input = input.share().map(IntoBuf::into_buf);

        // helper 1 initiates the query
        let query_id = self.drivers[0].start_query(query_config).await?;

        // Send inputs
        helpers_input
            .into_iter()
            .enumerate()
            .map(|(i, input)| {
                self.drivers[i].execute_query(QueryInput {
                    query_id,
                    input_stream: input.into(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(query_id)
    }

    /// ## Errors
    /// Propagates errors retrieving the query status.
    /// ## Panics
    /// Never.
    pub fn query_status(&self, query_id: QueryId) -> Result<[QueryStatus; 3], ApiError> {
        Ok((0..3)
            .map(|i| self.drivers[i].query_status(query_id))
            .collect::<Result<Vec<_>, _>>()?
            .try_into()
            .unwrap())
    }

    /// ## Errors
    /// Returns an error if one or more helpers can't finish the processing.
    /// ## Panics
    /// Never.
    pub async fn complete_query(&self, query_id: QueryId) -> Result<[Vec<u8>; 3], ApiError> {
        let results =
            try_join3_array([0, 1, 2].map(|i| self.drivers[i].complete_query(query_id))).await;
        self.mpc_network.reset();
        self.shard_network.reset();
        results
    }

    /// Initiates a new query on all helpers and drives it to completion.
    ///
    /// ## Errors
    /// Returns an error if it can't start a query or one or more helpers can't finish the processing.
    #[allow(clippy::missing_panics_doc)]
    pub async fn execute_query<I, A>(
        &self,
        input: I,
        query_config: QueryConfig,
    ) -> Result<[Vec<u8>; 3], ApiError>
    where
        I: IntoShares<A>,
        A: IntoBuf,
    {
        let query_id = self.start_query(input, query_config).await?;
        self.complete_query(query_id).await
    }
}
