use std::future::Future;
use std::pin::Pin;
use crate::helpers::query::{PrepareQuery, QueryConfig};
use crate::helpers::TransportError;
use crate::protocol::QueryId;

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
    pub receive_query: Box<dyn ReceiveQueryCallback<T>>,
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

