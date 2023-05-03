use crate::{
    helpers::{
        query::{QueryConfig, QueryInput},
        Transport, TransportCallbacks, TransportImpl,
    },
    protocol::QueryId,
    query::{NewQueryError, QueryCompletionError, QueryInputError, QueryProcessor},
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
    pub fn new() -> (Self, TransportCallbacks<TransportImpl>) {
        let query_processor = Arc::new(QueryProcessor::default());
        let this = Self {
            query_processor: Arc::clone(&query_processor),
        };

        // TODO: weak reference to query processor to prevent mem leak
        (this, Self::callbacks(&query_processor))
    }

    /// Instantiate [`HelperApp`] by connecting it to the provided transport implementation
    pub fn connect(self, transport: TransportImpl) -> HelperApp {
        HelperApp::new(transport, self.query_processor)
    }

    /// Create callbacks that tie up query processor and transport.
    fn callbacks(query_processor: &Arc<QueryProcessor>) -> TransportCallbacks<TransportImpl> {
        let rqp = Arc::clone(query_processor);
        let pqp = Arc::clone(query_processor);
        let iqp = Arc::clone(query_processor);
        let cqp = Arc::clone(query_processor);

        TransportCallbacks {
            receive_query: Box::new(move |transport: TransportImpl, receive_query| {
                let processor = Arc::clone(&rqp);
                Box::pin(async move {
                    let r = processor.new_query(transport, receive_query).await?;

                    Ok(r.query_id)
                })
            }),
            prepare_query: Box::new(move |transport: TransportImpl, prepare_query| {
                let processor = Arc::clone(&pqp);
                Box::pin(async move { processor.prepare(&transport, prepare_query) })
            }),
            query_input: Box::new(move |transport: TransportImpl, query_input| {
                let processor = Arc::clone(&iqp);
                Box::pin(async move { processor.receive_inputs(transport, query_input) })
            }),
            complete_query: Box::new(move |_transport: TransportImpl, query_id| {
                let processor = Arc::clone(&cqp);
                Box::pin(async move { processor.complete(query_id).await })
            }),
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
    pub async fn start_query(&self, query_config: QueryConfig) -> Result<QueryId, NewQueryError> {
        Ok(self
            .query_processor
            .new_query(Transport::clone_ref(&self.transport), query_config)
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

/// Union of error types returned by API operations.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    NewQuery(#[from] NewQueryError),
    #[error(transparent)]
    QueryInput(#[from] QueryInputError),
    #[error(transparent)]
    QueryCompletion(#[from] QueryCompletionError),
}
