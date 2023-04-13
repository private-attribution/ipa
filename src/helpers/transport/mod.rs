use crate::{
    helpers::HelperIdentity,
    protocol::{QueryId, Step},
};
use async_trait::async_trait;
use futures::Stream;
use std::{borrow::Borrow, io};

mod bytearrstream;
mod callbacks;
pub mod query;

use crate::error::BoxError;
pub use bytearrstream::{AlignedByteArrStream, ByteArrStream};
pub use callbacks::{PrepareQueryCallback, ReceiveQueryCallback, TransportCallbacks};

pub trait ResourceIdentifier: Sized {}
pub trait QueryIdBinding: Sized
where
    Option<QueryId>: From<Self>,
{
}
pub trait StepBinding: Sized
where
    Option<Step>: From<Self>,
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

impl From<NoStep> for Option<Step> {
    fn from(_: NoStep) -> Self {
        None
    }
}

impl StepBinding for NoStep {}
impl StepBinding for Step {}

pub trait RouteParams<R: ResourceIdentifier, Q: QueryIdBinding, S: StepBinding>: Send
where
    Option<QueryId>: From<Q>,
    Option<Step>: From<S>,
{
    type Params: Borrow<str>;

    fn resource_identifier(&self) -> R;
    fn query_id(&self) -> Q;
    fn step(&self) -> S;

    fn extra(&self) -> Self::Params;
}

impl RouteParams<NoResourceIdentifier, QueryId, Step> for (QueryId, Step) {
    type Params = &'static str;

    fn resource_identifier(&self) -> NoResourceIdentifier {
        NoResourceIdentifier
    }

    fn query_id(&self) -> QueryId {
        self.0
    }

    fn step(&self) -> Step {
        self.1.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

impl RouteParams<RouteId, QueryId, Step> for (RouteId, QueryId, Step) {
    type Params = &'static str;

    fn resource_identifier(&self) -> RouteId {
        self.0
    }

    fn query_id(&self) -> QueryId {
        self.1
    }

    fn step(&self) -> Step {
        self.2.clone()
    }

    fn extra(&self) -> Self::Params {
        ""
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error(transparent)]
    Io {
        #[from]
        inner: io::Error,
    },
    #[error("Error from remote helper {dest:?}: {inner:?}")]
    Rejected {
        dest: HelperIdentity,
        #[source]
        inner: BoxError,
    },
}

/// Transport that supports per-query,per-step channels
#[async_trait]
pub trait Transport: Clone + Send + Sync + 'static {
    type RecordsStream: Stream<Item = Vec<u8>> + Send + Unpin;

    fn identity(&self) -> HelperIdentity;

    /// Sends a new request to the given destination helper party.
    /// The contract for this method requires it to block until the request is acknowledged by
    /// the remote party. For streaming requests where body is large, only request headers are
    /// expected to be acknowledged)
    async fn send<D, Q, S, R>(&self, dest: HelperIdentity, route: R, data: D) -> Result<(), Error>
    where
        Option<QueryId>: From<Q>,
        Option<Step>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>,
        D: Stream<Item = Vec<u8>> + Send + 'static;

    /// Return the stream of records to be received from another helper for the specific query
    /// and step
    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Self::RecordsStream;
}
