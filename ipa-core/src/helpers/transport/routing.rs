use std::{borrow::Borrow, fmt::Debug};

use serde::de::DeserializeOwned;

use crate::{
    helpers::{QueryIdBinding, RouteParams, StepBinding, TransportIdentity},
    protocol::{Gate, QueryId},
};

// The type of request made to an MPC helper.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum RouteId {
    Records,
    ReceiveQuery,
    PrepareQuery,
    QueryInput,
    /// To accelerate delivery, we made some compromise here and as a result this API
    /// has double-meaning depending on the context.
    /// In the context of a shard, it is used to check whether other shards have the
    /// same status
    /// In the context of an MPC client, it is used to fetch the latest status of a given query.
    ///
    /// We should've used a different `RouteId` to differentiate those
    QueryStatus,
    CompleteQuery,
    KillQuery,
    Metrics,
}

/// The header/metadata of the incoming request.
#[derive(Debug)]
pub struct Addr<I> {
    pub route: RouteId,
    pub origin: Option<I>,
    pub query_id: Option<QueryId>,
    pub gate: Option<Gate>,
    // String and not vec for readability
    pub params: String,
}

impl<I: TransportIdentity> Addr<I> {
    #[allow(clippy::needless_pass_by_value)] // to avoid using double-reference at callsites
    pub fn from_route<Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>>(
        origin: Option<I>,
        route: R,
    ) -> Self
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        Self {
            route: route.resource_identifier(),
            origin,
            query_id: route.query_id().into(),
            gate: route.gate().into(),
            params: route.extra().borrow().to_string(),
        }
    }

    /// Drop the origin value and convert this into a request for a different identity type.
    /// Useful when we need to handle this request in both shard and MPC handlers.
    pub fn erase_origin<T: TransportIdentity>(self) -> Addr<T> {
        Addr {
            route: self.route,
            origin: None,
            query_id: self.query_id,
            gate: self.gate,
            params: self.params,
        }
    }

    /// Deserializes JSON-encoded request parameters into a client-supplied type `T`.
    ///
    /// ## Errors
    /// If deseserialization fails
    pub fn into<T: DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_str(&self.params)
    }

    #[cfg(all(test, unit_test))]
    pub fn records(from: I, query_id: QueryId, gate: Gate) -> Self {
        Self {
            route: RouteId::Records,
            origin: Some(from),
            query_id: Some(query_id),
            gate: Some(gate),
            params: String::new(),
        }
    }
}
