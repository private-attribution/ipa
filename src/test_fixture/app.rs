use crate::{
    error::Error,
    ff::Serializable,
    helpers::{
        query::{QueryConfig, QueryInput},
        ByteArrStream, HelperIdentity, Transport, TransportError,
    },
    protocol::QueryId,
    query::QueryProcessor,
    secret_sharing::IntoShares,
    test_fixture::{
        network::{InMemoryNetwork, InMemoryTransport, Network, TransportCallbacks},
        TestWorld,
    },
};
use futures_util::{future::try_join_all, FutureExt};
use generic_array::GenericArray;
use rand::thread_rng;
use std::{
    borrow::Borrow,
    fmt::Debug,
    sync::{Arc, Weak},
};
use typenum::Unsigned;

pub trait IntoBuf {
    fn into_buf(self) -> Vec<u8>;
}

impl<I: IntoIterator<Item = S>, S: Serializable> IntoBuf for I {
    fn into_buf(self) -> Vec<u8> {
        let this = self.into_iter();
        let (lb, ub) = this.size_hint();
        let cnt = ub.unwrap_or(lb);
        let item_size: usize = <S as Serializable>::Size::USIZE;

        let mut buf = vec![0u8; cnt * item_size];
        for (i, item) in this.enumerate() {
            let mut sl = &mut buf[i * item_size..(i + 1) * item_size];
            item.serialize(GenericArray::from_mut_slice(sl));
        }
        buf
    }
}

/// [`TestApp`] runs IPA queries end-to-end using [`InMemoryNetwork`]
/// It orchestrates the interaction between several components to drive queries to completion.
///
/// [`InMemoryNetwork`]: crate::test_fixture::network::InMemoryNetwork
pub struct TestApp {
    query_processors: [Arc<QueryProcessor>; 3],
    network: InMemoryNetwork,
}

struct AppDriver<T: Transport> {
    query_processor: Arc<QueryProcessor>,
    transport: T,
}

impl TestApp {
    pub fn new() -> Self {
        let processors = [
            QueryProcessor::default(),
            QueryProcessor::default(),
            QueryProcessor::default(),
        ]
        .map(Arc::new);

        let callbacks = processors.clone().map(|p| AppDriver::callback(p));
        let network = InMemoryNetwork::new(callbacks);

        Self {
            query_processors: processors,
            network,
        }
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
        let transports = self.network.transports();

        // helper 1 initiates the query
        let running_query = self.query_processors[0]
            .new_query(&transports[0], query_config)
            .await?;

        // Send inputs and poll for completion
        for (i, input) in helpers_input.into_iter().enumerate() {
            self.query_processors[i].receive_inputs(
                transports[i].clone(),
                QueryInput {
                    query_id: running_query.query_id,
                    input_stream: ByteArrStream::from(input),
                },
            )?;
        }

        let r = try_join_all(self.query_processors.iter().map(|processor| {
            processor
                .complete(running_query.query_id)
                .map(|r| r.map(|r| r.into_bytes()))
        }))
        .await?;

        Ok(<[_; 3]>::try_from(r).unwrap())
    }
}

impl<T: Transport> AppDriver<T> {
    /// Create callbacks that tie up query processor and transport.
    fn callback(query_processor: Arc<QueryProcessor>) -> TransportCallbacks<'static, T> {
        let callbacks = TransportCallbacks {
            receive_query: {
                let processor = query_processor.clone();
                Box::new(move |transport: T, receive_query| {
                    Box::pin({
                        // I don't know how to convince Rust compiler that this block owns
                        // processor
                        let processor = processor.clone();
                        async move {
                            let dest = transport.identity();
                            let r = processor
                                .new_query(&transport, receive_query)
                                .await
                                .map_err(|e| TransportError::Rejected {
                                    dest,
                                    inner: Box::new(e),
                                })?;

                            Ok(r.query_id)
                        }
                    })
                })
            },
            prepare_query: {
                let processor = query_processor.clone();
                Box::new(move |transport: T, prepare_query| {
                    Box::pin({
                        let processor = processor.clone();
                        async move {
                            let dest = transport.identity();
                            processor
                                .prepare(&transport, prepare_query)
                                .await
                                .map_err(|e| TransportError::Rejected {
                                    dest,
                                    inner: Box::new(e),
                                })
                        }
                    })
                })
            },
        };

        callbacks
    }
}
