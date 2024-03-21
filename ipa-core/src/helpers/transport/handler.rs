use std::{
    fmt::{Debug, Formatter},
    future::Future,
    marker::PhantomData,
};

use async_trait::async_trait;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::{
    error::BoxError,
    helpers::{
        query::PrepareQuery, transport::routing::Addr, BodyStream, HelperIdentity,
        TransportIdentity,
    },
    query::{
        NewQueryError, PrepareQueryError, ProtocolResult, QueryCompletionError, QueryInputError,
        QueryStatus, QueryStatusError,
    },
};

/// Represents some response sent from MPC helper acting on a given request. It is rudimental now
/// because we sent everything as HTTP body, but it could evolve.
///
/// ## Performance
/// This implementation is far from being optimal. Between HTTP and transport layer, there exists
/// one round of serialization and deserialization to properly represent the types. It is not critical
/// to address, because MPC helpers have to handle a constant number of requests per query. Note
/// that all requests tagged with [`crate::helpers::transport::RouteId::Records`] are not routed
/// through [`RequestHandler`], so there is no penalty.
///
pub struct HelperResponse {
    body: Vec<u8>,
}

impl Debug for HelperResponse {
    fn fmt(&self, _f: &mut Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}

impl HelperResponse {
    /// Returns an empty response that indicates that incoming request has been processed successfully
    #[must_use]
    pub fn ok() -> Self {
        Self { body: Vec::new() }
    }

    /// Consumes [`Self`] and returns the body of the response.
    #[must_use]
    pub fn into_body(self) -> Vec<u8> {
        self.body
    }

    /// Attempts to interpret [`Self`] body as JSON-serialized `T`.
    /// ## Errors
    /// if `T` cannot be deserialized from response body.
    pub fn try_into_owned<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_slice(&self.body)
    }
}

impl From<PrepareQuery> for HelperResponse {
    fn from(value: PrepareQuery) -> Self {
        let v = serde_json::to_vec(&json!({"query_id": value.query_id})).unwrap();
        Self { body: v }
    }
}

impl From<()> for HelperResponse {
    fn from(_value: ()) -> Self {
        Self::ok()
    }
}

impl From<QueryStatus> for HelperResponse {
    fn from(value: QueryStatus) -> Self {
        let v = serde_json::to_vec(&json!({"status": value})).unwrap();
        Self { body: v }
    }
}

impl<R: AsRef<dyn ProtocolResult>> From<R> for HelperResponse {
    fn from(value: R) -> Self {
        let v = value.as_ref().as_bytes();
        Self { body: v }
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
    QueryPrepare(#[from] PrepareQueryError),
    #[error(transparent)]
    QueryCompletion(#[from] QueryCompletionError),
    #[error(transparent)]
    QueryStatus(#[from] QueryStatusError),
    #[error(transparent)]
    DeserializationFailure(#[from] serde_json::Error),
    #[error("MalformedRequest: {0}")]
    BadRequest(BoxError),
}

/// Trait for custom-handling different request types made against MPC helper parties.
/// There is a limitation for RPITIT that traits can't be made object-safe, hence the use of async_trait
#[async_trait]
pub trait RequestHandler: Send + Sync {
    type Identity: TransportIdentity;
    /// Handle the incoming request with metadata/headers specified in [`Addr`] and body encoded as
    /// [`BodyStream`].
    async fn handle(
        &self,
        req: Addr<Self::Identity>,
        data: BodyStream,
    ) -> Result<HelperResponse, Error>;
}

#[async_trait]
impl<F> RequestHandler for F
where
    F: Fn(Addr<HelperIdentity>, BodyStream) -> Result<HelperResponse, Error>
        + Send
        + Sync
        + 'static,
{
    type Identity = HelperIdentity;

    async fn handle(
        &self,
        req: Addr<Self::Identity>,
        data: BodyStream,
    ) -> Result<HelperResponse, Error> {
        self(req, data)
    }
}

pub fn make_boxed_handler<'a, I, F, Fut>(handler: F) -> Box<dyn RequestHandler<Identity = I> + 'a>
where
    I: TransportIdentity,
    F: Fn(Addr<I>, BodyStream) -> Fut + Send + Sync + 'a,
    Fut: Future<Output = Result<HelperResponse, Error>> + Send + 'a,
{
    struct Handler<I, F> {
        inner: F,
        phantom: PhantomData<I>,
    }
    #[async_trait]
    impl<I, F, Fut> RequestHandler for Handler<I, F>
    where
        I: TransportIdentity,
        F: Fn(Addr<I>, BodyStream) -> Fut + Send + Sync,
        Fut: Future<Output = Result<HelperResponse, Error>> + Send,
    {
        type Identity = I;

        async fn handle(
            &self,
            req: Addr<Self::Identity>,
            data: BodyStream,
        ) -> Result<HelperResponse, Error> {
            (self.inner)(req, data).await
        }
    }

    Box::new(Handler {
        inner: handler,
        phantom: PhantomData,
    })
}

// This handler panics when [`Self::handle`] method is called.
pub struct PanickingHandler<I: TransportIdentity = HelperIdentity> {
    phantom: PhantomData<I>,
}

impl<I: TransportIdentity> Default for PanickingHandler<I> {
    fn default() -> Self {
        Self {
            phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<I: TransportIdentity> RequestHandler for PanickingHandler<I> {
    type Identity = I;

    async fn handle(
        &self,
        req: Addr<Self::Identity>,
        _data: BodyStream,
    ) -> Result<HelperResponse, Error> {
        panic!("unexpected call: {req:?}");
    }
}
