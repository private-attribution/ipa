use std::io;
use crate::{
    helpers::HelperIdentity,
    protocol::{QueryId, Step},
};
use async_trait::async_trait;
use futures::Stream;

pub mod query;
mod bytearrstream;

pub use bytearrstream::{AlignedByteArrStream, ByteArrStream};

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
    fn resource_identifier(&self) -> R;
    fn query_id(&self) -> Q;
    fn step(&self) -> S;

    fn extra(&self) -> &str;
}

impl RouteParams<NoResourceIdentifier, QueryId, Step> for (QueryId, Step) {
    fn resource_identifier(&self) -> NoResourceIdentifier {
        NoResourceIdentifier
    }

    fn query_id(&self) -> QueryId {
        self.0
    }

    fn step(&self) -> Step {
        self.1.clone()
    }

    fn extra(&self) -> &str {
        ""
    }
}

impl RouteParams<RouteId, QueryId, Step> for (RouteId, QueryId, Step) {
    fn resource_identifier(&self) -> RouteId {
        self.0
    }

    fn query_id(&self) -> QueryId {
        self.1
    }

    fn step(&self) -> Step {
        self.2.clone()
    }

    fn extra(&self) -> &str {
        ""
    }
}

/// Transport that supports per-query,per-step channels
#[async_trait]
pub trait Transport: Clone + Send + Sync + 'static {
    type RecordsStream: Stream<Item = Vec<u8>> + Send + Unpin;

    fn identity(&self) -> HelperIdentity;

    async fn send<D, Q, S, R>(
        &self,
        dest: HelperIdentity,
        route: R,
        data: D,
    ) -> Result<(), io::Error>
        where
            Option<QueryId>: From<Q>,
            Option<Step>: From<S>,
            Q: QueryIdBinding,
            S: StepBinding,
            R: RouteParams<RouteId, Q, S>,
            D: Stream<Item=Vec<u8>> + Send + 'static;

    /// Return the stream of records to be received from another helper for the specific query
    /// and step
    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Self::RecordsStream;
}

/// Enum to dispatch calls to various [`Transport`] implementations without the need
/// of dynamic dispatch. DD is not even possible with this trait, so that is the only way to prevent
/// [`Gateway`] to be generic over it. We want to avoid that as it pollutes our protocol code.
#[derive(Clone)]
pub enum TransportImpl {
    #[cfg(any(test, feature = "test-fixture"))]
    InMemory(std::sync::Weak<crate::test_fixture::transport::InMemoryChannelledTransport>)
}

#[async_trait]
impl Transport for TransportImpl {
    #[cfg(any(test, feature = "test-fixture"))]
    type RecordsStream = <std::sync::Weak<crate::test_fixture::transport::InMemoryChannelledTransport> as Transport>::RecordsStream;
    // TODO: it is likely that this ends up being the only type we could use here.
    #[cfg(not(any(test, feature = "test-fixture")))]
    type RecordsStream = std::pin::Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;

    fn identity(&self) -> HelperIdentity {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(ref inner) => inner.identity(),
            // https://github.com/rust-lang/rust/issues/78123
            _ => unreachable!()
        }
    }

    async fn send<D, Q, S, R>(&self, dest: HelperIdentity, route: R, data: D) -> Result<(), std::io::Error> where Option<QueryId>: From<Q>, Option<Step>: From<S>, Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>, D: Stream<Item=Vec<u8>> + Send + 'static {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(inner) => inner.send(dest, route, data).await,
            _ => unreachable!()
        }
    }

    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(&self, from: HelperIdentity, route: R) -> Self::RecordsStream {
        match self {
            #[cfg(any(test, feature = "test-fixture"))]
            TransportImpl::InMemory(inner) => inner.receive(from, route),
            _ => unreachable!()
        }
    }
}
