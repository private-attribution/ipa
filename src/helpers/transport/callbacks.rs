use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig},
        TransportError,
    },
    protocol::QueryId,
};
use std::{future::Future, pin::Pin};

/// Called when helper receives a new query request from an external party.
pub trait ReceiveQueryCallback<'a, T>:
    FnMut(
        T,
        QueryConfig,
    ) -> Pin<Box<dyn Future<Output = Result<QueryId, TransportError>> + Send + 'a>>
    + Send
{
}

impl<'a, T, F> ReceiveQueryCallback<'a, T> for F where
    F: FnMut(
            T,
            QueryConfig,
        ) -> Pin<Box<dyn Future<Output = Result<QueryId, TransportError>> + Send + 'a>>
        + Send
{
}

/// Called when helper receives a request from the coordinator to start working on a new query.
pub trait PrepareQueryCallback<'a, T>:
    FnMut(T, PrepareQuery) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>>
    + Send
{
}

impl<'a, T, F> PrepareQueryCallback<'a, T> for F where
    F: FnMut(
            T,
            PrepareQuery,
        ) -> Pin<Box<dyn Future<Output = Result<(), TransportError>> + Send + 'a>>
        + Send
{
}

pub struct TransportCallbacks<'a, T> {
    pub receive_query: Box<dyn ReceiveQueryCallback<'a, T>>,
    pub prepare_query: Box<dyn PrepareQueryCallback<'a, T>>,
}

impl<T> Default for TransportCallbacks<'_, T> {
    fn default() -> Self {
        Self {
            receive_query: Box::new(move |_, _| Box::pin(async { unimplemented!() })),
            prepare_query: Box::new(move |_, _| Box::pin(async { Ok(()) })),
        }
    }
}
