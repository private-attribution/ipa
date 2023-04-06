use crate::{
    helpers::query::{PrepareQuery, QueryConfig, QueryInput},
    protocol::QueryId,
    query::{
        NewQueryError, PrepareQueryError, ProtocolResult, QueryCompletionError, QueryInputError,
    },
};
use std::{future::Future, pin::Pin};

/// Macro for defining transport callbacks.
///
/// Each input definition specifies a callback name, a result type name, and
/// a function signature for the callback. The expansion looks like this:
///
/// ```ignore
/// pub type ReceiveQueryResult = Pin<Box<dyn Future<Output = Result<QueryId, NewQueryError>> + Send>>;
///
/// /// Called when helper receives a new query request from an external party.
/// pub trait ReceiveQueryCallback<T>:
///     Fn(T, QueryConfig) -> ReceiveQueryResult + Send + Sync {}
///
/// impl<T, F> ReceiveQueryCallback<T> for F where
///     F: Fn(T, QueryConfig) -> ReceiveQueryResult + Send + Sync {}
/// ```
macro_rules! callbacks {
    {
        $(
            $(#[$($attr:meta),+ ])?
            ($cb_name:ident, $res_name:ident): async fn($($args:ident),*) -> $result:ty;
        )*
    } => {
        $(
            pub type $res_name = Pin<Box<dyn Future<Output = $result> + Send>>;

            $(#[$($attr),+ ])?
            pub trait $cb_name<T>: Fn($($args),*) -> $res_name + Send + Sync {}

            impl<T, F> $cb_name<T> for F where
                F: Fn($($args),*) -> $res_name + Send + Sync {}
        )*
    }
}

callbacks! {
    /// Called when helper receives a new query request from an external party.
    (ReceiveQueryCallback, ReceiveQueryResult):
        async fn(T, QueryConfig) -> Result<QueryId, NewQueryError>;

    /// Called when helper receives a request from the coordinator to start working on a new query.
    (PrepareQueryCallback, PrepareQueryResult):
        async fn(T, PrepareQuery) -> Result<(), PrepareQueryError>;

    (QueryInputCallback, QueryInputResult):
        async fn(T, QueryInput) -> Result<(), QueryInputError>;

    /// Called to drive query to completion and return results.
    (CompleteQueryCallback, CompleteQueryResult):
        async fn(T, QueryId) -> Result<Box<dyn ProtocolResult>, QueryCompletionError>;
}

pub struct TransportCallbacks<T> {
    pub receive_query: Box<dyn ReceiveQueryCallback<T>>,
    pub prepare_query: Box<dyn PrepareQueryCallback<T>>,
    pub query_input: Box<dyn QueryInputCallback<T>>,
    pub complete_query: Box<dyn CompleteQueryCallback<T>>,
}

#[cfg(any(test, feature = "test-fixture"))]
impl<T> Default for TransportCallbacks<T> {
    fn default() -> Self {
        Self {
            receive_query: Box::new(move |_, _| Box::pin(async { unimplemented!() })),
            prepare_query: Box::new(move |_, _| Box::pin(async { Ok(()) })),
            query_input: Box::new(move |_, _| Box::pin(async { unimplemented!() })),
            complete_query: Box::new(move |_, _| Box::pin(async { unimplemented!() })),
        }
    }
}
