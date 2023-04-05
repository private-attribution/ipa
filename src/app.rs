use crate::{
    error::Error,
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        Transport, TransportCallbacks, TransportError, TransportImpl,
    },
    protocol::QueryId,
    query::QueryProcessor,
    sync::Arc,
};

pub struct Setup {
    query_processor: Arc<QueryProcessor>,
}

/// The API layer to interact with a helper.
pub struct HelperApp {
    query_processor: Arc<QueryProcessor>,
    transport: TransportImpl,
}

impl Setup {
    pub fn new() -> (Self, TransportCallbacks<'static, TransportImpl>) {
        let query_processor = Arc::new(QueryProcessor::default());
        let this = Self {
            query_processor: Arc::clone(&query_processor),
        };

        // TODO: weak reference to query processor to prevent mem leak
        (this, Self::callback(query_processor))
    }

    pub fn connect(self, transport: TransportImpl) -> HelperApp {
        HelperApp::new(transport, self.query_processor)
    }

    /// Create callbacks that tie up query processor and transport.
    fn callback(
        query_processor: Arc<QueryProcessor>,
    ) -> TransportCallbacks<'static, TransportImpl> {
        let callbacks = TransportCallbacks {
            receive_query: {
                let processor = query_processor.clone();
                Box::new(move |transport: TransportImpl, receive_query| {
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
                Box::new(move |transport: TransportImpl, prepare_query| {
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

impl HelperApp {
    pub fn new(transport: TransportImpl, query_processor: Arc<QueryProcessor>) -> Self {
        Self {
            query_processor,
            transport,
        }
    }

    pub async fn start_query(&self, query_config: QueryConfig) -> Result<QueryId, Error> {
        Ok(self
            .query_processor
            .new_query(&self.transport, query_config)
            .await?
            .query_id)
    }

    pub async fn execute_query(&self, input: QueryInput) -> Result<Vec<u8>, Error> {
        let query_id = input.query_id;
        self.query_processor
            .receive_inputs(self.transport.clone(), input)?;

        Ok(self.query_processor.complete(query_id).await?.into_bytes())
    }
}
