use std::{future::Future, pin::Pin};

use crate::{
    helpers::query::{PrepareQuery, QueryConfig, QueryInput},
    protocol::QueryId,
    query::{
        NewQueryError, PrepareQueryError, ProtocolResult, QueryCompletionError, QueryInputError,
        QueryStatus, QueryStatusError,
    },
};

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
    /// Called by clients to initiate a new query.
    (ReceiveQueryCallback, ReceiveQueryResult):
        async fn(T, QueryConfig) -> Result<QueryId, NewQueryError>;

    /// Called by the leader helper to set up followers for a new query.
    (PrepareQueryCallback, PrepareQueryResult):
        async fn(T, PrepareQuery) -> Result<(), PrepareQueryError>;

    /// Called by clients to deliver query input data.
    (QueryInputCallback, QueryInputResult):
        async fn(T, QueryInput) -> Result<(), QueryInputError>;

    /// Called by clients to retrieve query status.
    (QueryStatusCallback, QueryStatusResult):
        async fn(T, QueryId) -> Result<QueryStatus, QueryStatusError>;

    /// Called by clients to drive query to completion and retrieve results.
    (CompleteQueryCallback, CompleteQueryResult):
        async fn(T, QueryId) -> Result<Box<dyn ProtocolResult>, QueryCompletionError>;
}

pub struct TransportCallbacks<T> {
    pub receive_query: Box<dyn ReceiveQueryCallback<T>>,
    pub prepare_query: Box<dyn PrepareQueryCallback<T>>,
    pub query_input: Box<dyn QueryInputCallback<T>>,
    pub query_status: Box<dyn QueryStatusCallback<T>>,
    pub complete_query: Box<dyn CompleteQueryCallback<T>>,
}

#[cfg(any(test, feature = "in-memory-infra"))]
impl<T> Default for TransportCallbacks<T> {
    fn default() -> Self {
        // `TransportCallbacks::default()` is commonly used with struct update syntax
        // (`..Default::default()`) to fill out the callbacks that aren't relevant to a particular
        // test. In that scenario, a call that does occur is "unexpected" in the sense the term
        // is used by mocks.
        Self {
            receive_query: Box::new(move |_, _| {
                Box::pin(async { panic!("unexpected call to receive_query") })
            }),
            prepare_query: Box::new(move |_, _| {
                Box::pin(async { panic!("unexpected call to prepare_query") })
            }),
            query_input: Box::new(move |_, _| {
                Box::pin(async { panic!("unexpected call to query_input") })
            }),
            query_status: Box::new(move |_, _| {
                Box::pin(async { panic!("unexpected call to query_status") })
            }),
            complete_query: Box::new(move |_, _| {
                Box::pin(async { panic!("unexpected call to complete_query") })
            }),
        }
    }
}
