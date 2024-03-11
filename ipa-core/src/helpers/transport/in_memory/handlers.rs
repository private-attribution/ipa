use std::{collections::HashSet, future::Future};

use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig},
        transport::in_memory::{routing::Addr, transport::Error, InMemoryTransport},
        HelperIdentity, RouteId, Transport, TransportCallbacks, TransportIdentity,
    },
    protocol::QueryId,
    sharding::ShardIndex,
};

///
pub trait RequestHandler<I: TransportIdentity>: Send {
    fn handle(
        &mut self,
        transport: InMemoryTransport<I>,
        addr: Addr<I>,
    ) -> impl Future<Output = Result<(), Error<I>>> + Send;
}

/// Helper trait to bind in-memory request handlers to transport identity.
pub trait IdentityHandlerExt: TransportIdentity {
    type Handler: RequestHandler<Self>;
}

impl IdentityHandlerExt for HelperIdentity {
    type Handler = HelperRequestHandler;
}

impl IdentityHandlerExt for ShardIndex {
    type Handler = ();
}

impl RequestHandler<ShardIndex> for () {
    async fn handle(
        &mut self,
        _transport: InMemoryTransport<ShardIndex>,
        addr: Addr<ShardIndex>,
    ) -> Result<(), Error<ShardIndex>> {
        panic!(
            "Shards can only process {:?} requests, got {:?}",
            RouteId::Records,
            addr.route
        )
    }
}

/// Handler that keeps track of running queries and
/// routes [`RouteId::PrepareQuery`] and [`RouteId::ReceiveQuery`] requests to the stored
/// callback instance. This handler works for MPC networks, for sharding network see
/// [`RequestHandler<ShardIndex>`]
pub struct HelperRequestHandler {
    active_queries: HashSet<QueryId>,
    callbacks: TransportCallbacks<InMemoryTransport<HelperIdentity>>,
}

impl From<TransportCallbacks<InMemoryTransport<HelperIdentity>>> for HelperRequestHandler {
    fn from(callbacks: TransportCallbacks<InMemoryTransport<HelperIdentity>>) -> Self {
        Self {
            active_queries: HashSet::default(),
            callbacks,
        }
    }
}

impl RequestHandler<HelperIdentity> for HelperRequestHandler {
    async fn handle(
        &mut self,
        transport: InMemoryTransport<HelperIdentity>,
        addr: Addr<HelperIdentity>,
    ) -> Result<(), Error<HelperIdentity>> {
        let dest = transport.identity();
        match addr.route {
            RouteId::ReceiveQuery => {
                let qc = addr.into::<QueryConfig>();
                (self.callbacks.receive_query)(Transport::clone_ref(&transport), qc)
                    .await
                    .map(|query_id| {
                        assert!(
                            self.active_queries.insert(query_id),
                            "the same query id {query_id:?} is generated twice"
                        );
                    })
                    .map_err(|e| Error::Rejected {
                        dest,
                        inner: Box::new(e),
                    })
            }
            RouteId::PrepareQuery => {
                let input = addr.into::<PrepareQuery>();
                (self.callbacks.prepare_query)(Transport::clone_ref(&transport), input)
                    .await
                    .map_err(|e| Error::Rejected {
                        dest,
                        inner: Box::new(e),
                    })
            }
            RouteId::Records => unreachable!(),
        }
    }
}
