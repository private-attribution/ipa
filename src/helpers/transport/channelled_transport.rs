use std::io;

use crate::helpers::HelperIdentity;
use futures::Stream;

use crate::protocol::{QueryId, Step};
use async_trait::async_trait;

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
pub trait ChannelledTransport: Send + Sync + 'static {
    type DataStream: Stream<Item = Vec<u8>>;
    type RecordsStream: Stream<Item = Vec<u8>>;

    fn identity(&self) -> HelperIdentity;

    async fn send<Q, S, R>(
        &self,
        dest: HelperIdentity,
        route: R,
        data: Self::DataStream,
    ) -> Result<(), io::Error>
    where
        Option<QueryId>: From<Q>,
        Option<Step>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S>;

    /// Return the stream of records to be received from another helper for the specific query
    /// and step
    fn receive<R: RouteParams<NoResourceIdentifier, QueryId, Step>>(
        &self,
        from: HelperIdentity,
        route: R,
    ) -> Self::RecordsStream;
}
