use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig},
        TransportError,
    },
    protocol::QueryId,
};
use std::{future::Future, pin::Pin};

/// Called when helper receives a new query request from an external party.
pub trait ReceiveQueryCallback<T>:
    FnMut(T, QueryConfig) -> Pin<Box<dyn Future<Output = Result<QueryId, TransportError>> + Send>>
    + Send
{
}

impl<T, F> ReceiveQueryCallback<T> for F where
    F: FnMut(
            T,
            QueryConfig,
        ) -> Pin<Box<dyn Future<Output = Result<QueryId, TransportError>> + Send>>
        + Send
{
}

/// Called when helper receives a request from the coordinator to start working on a new query.
pub trait PrepareQueryCallback<T>:
    FnMut(T, PrepareQuery) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send>> + Send
{
}

impl<T, F> PrepareQueryCallback<T> for F where
    F: FnMut(T, PrepareQuery) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send>>
        + Send
{
}

pub struct TransportCallbacks<T> {
    pub receive_query: Box<dyn ReceiveQueryCallback<T>>,
    pub prepare_query: Box<dyn PrepareQueryCallback<T>>,
}

#[cfg(any(test, feature = "test-fixture"))]
impl<T> Default for TransportCallbacks<T> {
    fn default() -> Self {
        Self {
            receive_query: Box::new(move |_, _| Box::pin(async { unimplemented!() })),
            prepare_query: Box::new(move |_, _| Box::pin(async { Ok(()) })),
        }
    }
}
