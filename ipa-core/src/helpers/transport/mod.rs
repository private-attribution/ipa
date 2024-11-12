use std::{
    borrow::{Borrow, Cow},
    fmt::Debug,
    hash::Hash,
};

use async_trait::async_trait;
use futures::{stream::FuturesUnordered, FutureExt, Stream, StreamExt};

#[cfg(feature = "in-memory-infra")]
use crate::helpers::in_memory_config::InspectContext;
use crate::{
    helpers::{transport::routing::RouteId, HelperIdentity, Role, TransportIdentity},
    protocol::{Gate, QueryId},
    sharding::ShardIndex,
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
pub use in_memory::{config, InMemoryMpcNetwork, InMemoryShardNetwork, InMemoryTransport};
use ipa_metrics::LabelValue;
pub use receive::{LogErrors, ReceiveRecords};
#[cfg(feature = "web-app")]
pub use stream::WrappedAxumBodyStream;
pub use stream::{
    BodyStream, BytesStream, LengthDelimitedStream, RecordsStream, SingleRecordStream,
    StreamCollection, StreamKey, WrappedBoxBodyStream,
};

/// An identity of a peer that can be communicated with using [`Transport`]. There are currently two
/// types of peers - helpers and shards.
pub trait Identity:
    Copy + Clone + Debug + PartialEq + Eq + PartialOrd + Ord + Hash + Send + Sync + LabelValue + 'static
{
    fn as_str(&self) -> Cow<'static, str>;

    /// Parses a ref to a string representation of this identity
    ///
    /// # Errors
    /// If there where any problems parsing the identity.
    fn from_str(s: &str) -> Result<Self, crate::error::Error>;

    /// Returns a 0-based index suitable to index Vec or other containers.
    fn as_index(&self) -> usize;

    #[cfg(feature = "in-memory-infra")]
    fn inspect_context(
        &self,
        shard: Option<ShardIndex>,
        helper: HelperIdentity,
        gate: Gate,
    ) -> InspectContext;
}

impl Identity for ShardIndex {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Owned(self.to_string())
    }

    fn from_str(s: &str) -> Result<Self, crate::error::Error> {
        s.parse::<u32>()
            .map_err(|_e| {
                crate::error::Error::InvalidId(format!("The string {s} is an invalid Shard Index"))
            })
            .map(ShardIndex::from)
    }

    fn as_index(&self) -> usize {
        usize::from(*self)
    }

    #[cfg(feature = "in-memory-infra")]
    fn inspect_context(
        &self,
        shard: Option<ShardIndex>,
        helper: HelperIdentity,
        gate: Gate,
    ) -> InspectContext {
        InspectContext::ShardMessage {
            helper,
            source: shard.unwrap(),
            dest: *self,
            gate,
        }
    }
}

impl Identity for HelperIdentity {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Borrowed(match *self {
            Self::ONE => Self::ONE_STR,
            Self::TWO => Self::TWO_STR,
            Self::THREE => Self::THREE_STR,
            _ => unreachable!(),
        })
    }

    fn from_str(s: &str) -> Result<Self, crate::error::Error> {
        match s {
            Self::ONE_STR => Ok(Self::ONE),
            Self::TWO_STR => Ok(Self::TWO),
            Self::THREE_STR => Ok(Self::THREE),
            _ => Err(crate::error::Error::InvalidId(format!(
                "The string {s} is an invalid Helper Identity"
            ))),
        }
    }

    fn as_index(&self) -> usize {
        usize::from(self.id) - 1
    }

    #[cfg(feature = "in-memory-infra")]
    fn inspect_context(
        &self,
        shard: Option<ShardIndex>,
        helper: HelperIdentity,
        gate: Gate,
    ) -> InspectContext {
        InspectContext::MpcMessage {
            shard,
            source: helper,
            dest: *self,
            gate,
        }
    }
}

/// Role is an identifier of helper peer, only valid within a given query. For every query, there
/// exists a static mapping from role to helper identity.
impl Identity for Role {
    fn as_str(&self) -> Cow<'static, str> {
        Cow::Borrowed(Role::as_static_str(self))
    }

    fn from_str(s: &str) -> Result<Self, crate::error::Error> {
        match s {
            Self::H1_STR => Ok(Self::H1),
            Self::H2_STR => Ok(Self::H2),
            Self::H3_STR => Ok(Self::H3),
            _ => Err(crate::error::Error::InvalidId(format!(
                "The string {s} is an invalid Role"
            ))),
        }
    }

    fn as_index(&self) -> usize {
        match self {
            Self::H1 => 0,
            Self::H2 => 1,
            Self::H3 => 2,
        }
    }

    #[cfg(feature = "in-memory-infra")]
    fn inspect_context(
        &self,
        _shard: Option<ShardIndex>,
        _helper: HelperIdentity,
        _gate: Gate,
    ) -> InspectContext {
        unimplemented!("inspection should use helper identities, not roles")
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

#[derive(thiserror::Error, Debug)]
#[error("One or more peers rejected the request: {failures:?}")]
pub struct BroadcastError<I: TransportIdentity, E: Debug> {
    pub failures: Vec<(I, E)>,
}

impl<I: TransportIdentity, E: Debug> From<Vec<(I, E)>> for BroadcastError<I, E> {
    fn from(value: Vec<(I, E)>) -> Self {
        Self { failures: value }
    }
}

/// Transport that supports per-query,per-step channels
#[async_trait]
pub trait Transport: Clone + Send + Sync + 'static {
    type Identity: TransportIdentity;
    type RecordsStream: BytesStream;
    type Error: std::fmt::Debug + Send;

    /// Return my identity in the network (MPC or Sharded)
    fn identity(&self) -> Self::Identity;

    /// Returns all the other identities, besides me, in this network.
    fn peers(&self) -> impl Iterator<Item = Self::Identity>;

    /// The number of peers on the network. Default implementation may not be efficient,
    /// because it uses [`Self::peers`] to count, so implementations are encouraged to
    /// override it
    fn peer_count(&self) -> u32 {
        u32::try_from(self.peers().count()).expect("Number of peers is less than 4B")
    }

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

    /// Broadcasts a message to all peers, excluding this instance, collecting all failures and
    /// successes. This method waits for all responses and returns only when all peers responded.
    async fn broadcast<Q, S, R>(
        &self,
        route: R,
    ) -> Result<(), BroadcastError<Self::Identity, Self::Error>>
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
        Q: QueryIdBinding,
        S: StepBinding,
        R: RouteParams<RouteId, Q, S> + Clone,
    {
        let mut futs = FuturesUnordered::new();
        for peer_identity in self.peers() {
            futs.push(
                Self::send(self, peer_identity, route.clone(), futures::stream::empty())
                    .map(move |v| (peer_identity, v)),
            );
        }

        let mut errs = Vec::new();
        while let Some(r) = futs.next().await {
            if let Err(e) = r.1 {
                errs.push((r.0, e));
            }
        }

        if errs.is_empty() {
            Ok(())
        } else {
            Err(errs.into())
        }
    }

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

#[cfg(all(test, unit_test))]
mod tests {
    use crate::{
        helpers::{HelperIdentity, Role, TransportIdentity},
        sharding::ShardIndex,
    };

    #[test]
    fn helper_from_str() {
        assert_eq!(HelperIdentity::from_str("A").unwrap(), HelperIdentity::ONE);
        assert_eq!(HelperIdentity::from_str("B").unwrap(), HelperIdentity::TWO);
        assert_eq!(
            HelperIdentity::from_str("C").unwrap(),
            HelperIdentity::THREE
        );
    }

    #[test]
    #[should_panic(expected = "The string H1 is an invalid Helper Identity")]
    fn invalid_helper_from_str() {
        assert_eq!(HelperIdentity::from_str("H1").unwrap(), HelperIdentity::ONE);
    }

    #[test]
    fn shard_from_str() {
        assert_eq!(ShardIndex::from_str("42").unwrap(), ShardIndex::from(42));
        assert_eq!(ShardIndex::from_str("9").unwrap(), ShardIndex::from(9));
        assert_eq!(ShardIndex::from_str("0").unwrap(), ShardIndex::from(0));
    }

    #[test]
    #[should_panic(expected = "The string -1 is an invalid Shard Index")]
    fn invalid_shard_from_str() {
        assert_eq!(ShardIndex::from_str("-1").unwrap(), ShardIndex::from(0));
    }

    #[test]
    fn role_from_str() {
        assert_eq!(Role::from_str("H1").unwrap(), Role::H1);
        assert_eq!(Role::from_str("H2").unwrap(), Role::H2);
        assert_eq!(Role::from_str("H3").unwrap(), Role::H3);
    }

    #[test]
    #[should_panic(expected = "The string A is an invalid Role")]
    fn invalid_role_from_str() {
        assert_eq!(Role::from_str("A").unwrap(), Role::H1);
    }
}
