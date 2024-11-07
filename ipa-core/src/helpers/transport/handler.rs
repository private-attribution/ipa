use std::{fmt::Debug, future::Future, marker::PhantomData};

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
        QueryKillStatus, QueryKilled, QueryStatus, QueryStatusError,
    },
    sync::{Arc, Mutex, Weak},
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

/// The lifecycle of request handlers is somewhat complicated. First, to initialize [`Transport`],
/// an instance of [`RequestHandler`] is required upfront. To function properly, each handler must
/// have a reference to transport.
///
/// This lifecycle is managed through this struct. An empty [`Option`], protected by a mutex
/// is passed over to transport, and it is given a value later, after transport is fully initialized.
pub struct HandlerBox<I = HelperIdentity> {
    /// There is a cyclic dependency between handlers and transport.
    /// Handlers use transports to create MPC infrastructure as response to query requests.
    /// Transport uses handler to respond to requests.
    ///
    /// To break this cycle, transport holds a weak reference to the handler and handler
    /// uses strong references to transport.
    inner: Mutex<Option<Weak<dyn RequestHandler<I>>>>,
}

impl<I> Default for HandlerBox<I> {
    fn default() -> Self {
        Self {
            inner: Mutex::new(None),
        }
    }
}

impl<I: TransportIdentity> HandlerBox<I> {
    #[must_use]
    pub fn empty() -> HandlerRef<I> {
        HandlerRef {
            inner: Arc::new(Self::default()),
        }
    }

    pub fn owning_ref(handler: &Arc<dyn RequestHandler<I>>) -> HandlerRef<I> {
        HandlerRef {
            inner: Arc::new(Self {
                inner: Mutex::new(Some(Arc::downgrade(handler))),
            }),
        }
    }

    fn set_handler(&self, handler: Weak<dyn RequestHandler<I>>) {
        let mut guard = self.inner.lock().unwrap();
        assert!(guard.is_none(), "Handler can be set only once");
        *guard = Some(handler);
    }

    fn handler(&self) -> Arc<dyn RequestHandler<I>> {
        self.inner
            .lock()
            .unwrap()
            .as_ref()
            .expect("Handler is set")
            .upgrade()
            .expect("Handler is not destroyed")
    }
}

/// This struct is passed over to [`Transport`] to initialize it.
#[derive(Clone)]
pub struct HandlerRef<I = HelperIdentity> {
    inner: Arc<HandlerBox<I>>,
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

impl From<QueryKilled> for HelperResponse {
    fn from(value: QueryKilled) -> Self {
        let v = serde_json::to_vec(&json!({"query_id": value.0, "status": "killed"})).unwrap();
        Self { body: v }
    }
}

impl<R: AsRef<dyn ProtocolResult>> From<R> for HelperResponse {
    fn from(value: R) -> Self {
        let v = value.as_ref().to_bytes();
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
    QueryKill(#[from] QueryKillStatus),
    #[error(transparent)]
    DeserializationFailure(#[from] serde_json::Error),
    #[error("MalformedRequest: {0}")]
    BadRequest(BoxError),
}

/// Trait for custom-handling different request types made against MPC helper parties.
/// There is a limitation for RPITIT that traits can't be made object-safe, hence the use of async_trait
#[async_trait]
pub trait RequestHandler<I: TransportIdentity>: Send + Sync {
    /// Handle the incoming request with metadata/headers specified in [`Addr`] and body encoded as
    /// [`BodyStream`].
    async fn handle(&self, req: Addr<I>, data: BodyStream) -> Result<HelperResponse, Error>;
}

pub fn make_owned_handler<'a, I, F, Fut>(handler: F) -> Arc<dyn RequestHandler<I> + 'a>
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
    impl<I, F, Fut> RequestHandler<I> for Handler<I, F>
    where
        I: TransportIdentity,
        F: Fn(Addr<I>, BodyStream) -> Fut + Send + Sync,
        Fut: Future<Output = Result<HelperResponse, Error>> + Send,
    {
        async fn handle(&self, req: Addr<I>, data: BodyStream) -> Result<HelperResponse, Error> {
            (self.inner)(req, data).await
        }
    }

    Arc::new(Handler {
        inner: handler,
        phantom: PhantomData,
    })
}

impl<I: TransportIdentity> HandlerRef<I> {
    pub fn set_handler(&self, handler: Weak<dyn RequestHandler<I>>) {
        self.inner.set_handler(handler);
    }
}

#[async_trait]
impl<I: TransportIdentity> RequestHandler<I> for HandlerRef<I> {
    async fn handle(&self, req: Addr<I>, data: BodyStream) -> Result<HelperResponse, Error> {
        self.inner.handler().handle(req, data).await
    }
}
