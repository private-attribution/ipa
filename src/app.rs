use crate::{
    error::Error,
    helpers::{
        query::{QueryConfig, QueryInput},
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
#[must_use]
pub struct HelperApp {
    query_processor: Arc<QueryProcessor>,
    transport: TransportImpl,
}

impl Setup {
    #[must_use]
    pub fn new() -> (Self, TransportCallbacks<'static, TransportImpl>) {
        let query_processor = Arc::new(QueryProcessor::default());
        let this = Self {
            query_processor: Arc::clone(&query_processor),
        };

        // TODO: weak reference to query processor to prevent mem leak
        (this, Self::callback(&query_processor))
    }

    /// Instantiate [`HelperApp`] by connecting it to the provided transport implementation
    pub fn connect(self, transport: TransportImpl) -> HelperApp {
        HelperApp::new(transport, self.query_processor)
    }

    /// Create callbacks that tie up query processor and transport.
    fn callback(
        query_processor: &Arc<QueryProcessor>,
    ) -> TransportCallbacks<'static, TransportImpl> {
        TransportCallbacks {
            receive_query: {
                let processor = Arc::clone(query_processor);
                Box::new(move |transport: TransportImpl, receive_query| {
                    Box::pin({
                        // I don't know how to convince Rust compiler that this block owns
                        // processor.
                        let processor = Arc::clone(&processor);
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
                let processor = Arc::clone(query_processor);
                Box::new(move |transport: TransportImpl, prepare_query| {
                    Box::pin({
                        let processor = Arc::clone(&processor);
                        async move {
                            let dest = transport.identity();
                            processor.prepare(&transport, prepare_query).map_err(|e| {
                                TransportError::Rejected {
                                    dest,
                                    inner: Box::new(e),
                                }
                            })
                        }
                    })
                })
            },
        }
    }
}

impl HelperApp {
    pub fn new(transport: TransportImpl, query_processor: Arc<QueryProcessor>) -> Self {
        Self {
            query_processor,
            transport,
        }
    }

    /// Initiates a new query on this helper. In case if query is accepted, the unique [`QueryId`]
    /// identifier is returned, otherwise an error indicating what went wrong is reported back.
    ///
    /// ## Errors
    /// If query is rejected for any reason.
    pub async fn start_query(&self, query_config: QueryConfig) -> Result<QueryId, Error> {
        Ok(self
            .query_processor
            .new_query(&self.transport, query_config)
            .await?
            .query_id)
    }

    /// Drives the given query to completion by providing the inputs to it and awaiting the results
    /// of the computation.
    ///
    /// ## Errors
    /// If a query with the given id is not running on this helper or if an error occurred while
    /// processing this query.
    pub async fn execute_query(&self, input: QueryInput) -> Result<Vec<u8>, Error> {
        let query_id = input.query_id;
        let transport = <TransportImpl as Clone>::clone(&self.transport);
        self.query_processor.receive_inputs(transport, input)?;

        Ok(self.query_processor.complete(query_id).await?.into_bytes())
    }
}
