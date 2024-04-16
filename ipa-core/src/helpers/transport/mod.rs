use std::{
    borrow::{Borrow, Cow},
    fmt::Debug,
    hash::Hash,
};

use async_trait::async_trait;
use futures::Stream;

use crate::{
    helpers::HelperIdentity,
    protocol::{step::Gate, QueryId},
};

mod handler;
#[cfg(feature = "in-memory-infra")]
mod in_memory;
pub mod query;
mod receive;
pub mod routing;
mod stream;

pub use handler::{
    make_owned_handler, Error as ApiError, HandlerBox, HandlerRef, HelperResponse, RequestHandler,
};
#[cfg(feature = "in-memory-infra")]
pub use in_memory::{InMemoryMpcNetwork, InMemoryShardNetwork, InMemoryTransport};
pub use receive::{LogErrors, ReceiveRecords};
#[cfg(feature = "web-app")]
pub use stream::WrappedAxumBodyStream;
pub use stream::{
    BodyStream, BytesStream, LengthDelimitedStream, RecordsStream, SingleRecordStream,
    StreamCollection, StreamKey, WrappedBoxBodyStream,
};

use crate::{
    helpers::{transport::routing::RouteId, Role, TransportIdentity},
    sharding::ShardIndex,
};

/// An identity of a peer that can be communicated with using [`Transport`]. There are currently two
/// types of peers - helpers and shards.
pub trait Identity:
    Copy + Clone + Debug + PartialEq + Eq + PartialOrd + Ord + Hash + Send + Sync + 'static
{
    fn as_str(&self) -> Cow<'static, str>;
}

impl Identity for ShardIndex {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }
}
impl Identity for HelperIdentity {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Owned(self.id.to_string())
    }
}

/// Role is an identifier of helper peer, only valid within a given query. For every query, there
/// exists a static mapping from role to helper identity.
impl Identity for Role {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Borrowed(Role::as_static_str(self))
    }
}

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

impl ResourceIdentifier for NoResourceIdentifier {}
impl ResourceIdentifier for RouteId {}

impl From<NoQueryId> for Option<QueryId> {
    fn from(_: NoQueryId) -> Self {
        None
    }
}

impl QueryIdBinding for NoQueryId {}
impl QueryIdBinding for QueryId {}

impl From<NoStep> for Option<Gate> {
    fn from(_: NoStep) -> Self {
        None
    }
}

impl StepBinding for NoStep {}
impl StepBinding for Gate {}

pub trait RouteParams<R: ResourceIdentifier, Q: QueryIdBinding, S: StepBinding>: Send
where
    Option<QueryId>: From<Q>,
    Option<Gate>: From<S>,
{
    // This is not great and definitely not a zero-cost abstraction. We serialize parameters
    // here, only to deserialize them again inside the request handler. I am not too worried
    // about it as long as the data we serialize is tiny, which is the case right now.
    type Params: Borrow<str>;

    fn resource_identifier(&self) -> R;
    fn query_id(&self) -> Q;
    fn gate(&self) -> S;

    fn extra(&self) -> Self::Params;
}

impl RouteParams<NoResourceIdentifier, QueryId, Gate> for (QueryId, Gate) {
    type Params = &'static str;

    fn resource_identifier(&self) -> NoResourceIdentifier {
        NoResourceIdentifier
    }

    fn query_id(&self) -> QueryId {
        self.0
    }

    fn gate(&self) -> Gate {
        self.1.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

impl RouteParams<RouteId, QueryId, Gate> for (RouteId, QueryId, Gate) {
    type Params = &'static str;

    fn resource_identifier(&self) -> RouteId {
        self.0
    }

    fn query_id(&self) -> QueryId {
        self.1
    }

    fn gate(&self) -> Gate {
        self.2.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

impl RouteParams<RouteId, QueryId, NoStep> for (RouteId, QueryId) {
    type Params = &'static str;

    fn resource_identifier(&self) -> RouteId {
        self.0
    }

    fn query_id(&self) -> QueryId {
        self.1
    }

    fn gate(&self) -> NoStep {
        NoStep
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

/// Transport that supports per-query,per-step channels
#[async_trait]
pub trait Transport: Clone + Send + Sync + 'static {
    type Identity: TransportIdentity;
    type RecordsStream: BytesStream;
    type Error: std::fmt::Debug;

    fn identity(&self) -> Self::Identity;

    /// Sends a new request to the given destination helper party.
    /// Depending on the specific request, it may or may not require acknowledgment by the remote
    /// party
    async fn send<D, Q, S, R>(
        &self,
        dest: Self::Identity,
        route: R,
        data: D,
    ) -> Result<(), Self::Error>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
        D: Stream<Item = Vec<u8>> + Send + 'static;

    /// Return the stream of records to be received from another helper for the specific query
    /// and step
    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Gate>>(
        &self,
        from: Self::Identity,
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
