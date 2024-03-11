use std::borrow::Borrow;

use async_trait::async_trait;
use futures::Stream;
use ipa_step::Gate;

use crate::{helpers::HelperIdentity, protocol::QueryId};

pub mod callbacks;
#[cfg(feature = "in-memory-infra")]
mod in_memory;
pub mod query;
mod receive;
mod stream;

#[cfg(feature = "in-memory-infra")]
pub use in_memory::{InMemoryNetwork, InMemoryTransport};
pub use receive::{LogErrors, ReceiveRecords};
#[cfg(feature = "web-app")]
pub use stream::WrappedAxumBodyStream;
pub use stream::{
    BodyStream, BytesStream, LengthDelimitedStream, RecordsStream, StreamCollection, StreamKey,
    WrappedBoxBodyStream,
};

pub trait ResourceIdentifier: Sized {}
pub trait QueryIdBinding: Sized
where
    Option<QueryId>: From<Self>,
{
}
pub trait StepBinding: Sized
where
    Option<Gate>: From<Self>,
{
}

pub struct NoResourceIdentifier;
pub struct NoQueryId;
pub struct NoStep;

#[derive(Debug, Copy, Clone)]
pub enum RouteId {
    Records,
    ReceiveQuery,
    PrepareQuery,
}

impl ResourceIdentifier for NoResourceIdentifier {}
impl ResourceIdentifier for RouteId {}

impl From<NoQueryId> for Option<QueryId> {
    fn from(_: NoQueryId) -> Self {
        None
    }
}

impl QueryIdBinding for NoQueryId {}
impl QueryIdBinding for QueryId {}

impl<G: Gate> From<NoStep> for Option<G> {
    fn from(_: NoStep) -> Self {
        None
    }
}

impl StepBinding for NoStep {}
impl<G: Gate> StepBinding for G {}

pub trait RouteParams<G, R: ResourceIdentifier, Q: QueryIdBinding, S: StepBinding>: Send
where
    G: Gate,
    Option<QueryId>: From<Q>,
    Option<G>: From<S>,
{
    type Params: Borrow<str>;

    fn resource_identifier(&self) -> R;
    fn query_id(&self) -> Q;
    fn gate(&self) -> S;

    fn extra(&self) -> Self::Params;
}

impl<G: Gate> RouteParams<G, NoResourceIdentifier, QueryId, G> for (QueryId, G) {
    type Params = &'static str;

    fn resource_identifier(&self) -> NoResourceIdentifier {
        NoResourceIdentifier
    }

    fn query_id(&self) -> QueryId {
        self.0
    }

    fn gate(&self) -> G {
        self.1.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

impl<G: Gate> RouteParams<G, RouteId, QueryId, G> for (RouteId, QueryId, G) {
    type Params = &'static str;

    fn resource_identifier(&self) -> RouteId {
        self.0
    }

    fn query_id(&self) -> QueryId {
        self.1
    }

    fn gate(&self) -> G {
        self.2.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

/// Transport that supports per-query, per-step channels
#[async_trait]
pub trait Transport<G: Gate>: Clone + Send + Sync + 'static {
    type RecordsStream: Stream<Item = Vec<u8>> + Send + Unpin;
    type Error: std::fmt::Debug;

    fn identity(&self) -> HelperIdentity;

    /// Sends a new request to the given destination helper party.
    /// Depending on the specific request, it may or may not require acknowledgment by the remote
    /// party
    async fn send<D, Q, S, R>(
        &self,
        dest: HelperIdentity,
        route: R,
        data: D,
    ) -> Result<(), Self::Error>
    where
        Option<QueryId>: From<Q>,
        Option<G>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<G, RouteId, Q, S>,
        D: Stream<Item = Vec<u8>> + Send + 'static;

    /// Return the stream of records to be received from another helper for the specific query
    /// and step
    fn receive<R: RouteParams<G, NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Self::RecordsStream;

    /// Alias for `Clone::clone`.
    ///
    /// `Transport` is implemented for `Weak<InMemoryTranport>` and `Arc<HttpTransport>`. Clippy won't
    /// let us write `transport.clone()` since these are ref-counted pointer types, and neither
    /// `Arc::clone` or `Weak::clone` is universally correct. Thus `Transport::clone_ref`. Calling
    /// it `Transport::clone` would result in clashes anywhere both `Transport` and `Arc` are in-scope.
    #[must_use]
    fn clone_ref(&self) -> Self {
        <Self as Clone>::clone(self)
    }
}
