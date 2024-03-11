use std::{
    borrow::Borrow,
    fmt::{Debug, Formatter},
};

use serde::de::DeserializeOwned;

use crate::{
    helpers::{QueryIdBinding, RouteId, RouteParams, StepBinding, TransportIdentity},
    protocol::{step::Gate, QueryId},
};

/// The header/metadata of the incoming request.
pub(super) struct Addr<I> {
    pub route: RouteId,
    pub origin: Option<I>,
    pub query_id: Option<QueryId>,
    pub gate: Option<Gate>,
    pub params: String,
}

impl<I: TransportIdentity> Addr<I> {
    #[allow(clippy::needless_pass_by_value)] // to avoid using double-reference at callsites
    pub fn from_route<Q: QueryIdBinding, S: StepBinding, R: RouteParams<RouteId, Q, S>>(
        origin: I,
        route: R,
    ) -> Self
    where
        Option<QueryId>: From<Q>,
        Option<Gate>: From<S>,
    {
        Self {
            route: route.resource_identifier(),
            origin: Some(origin),
            query_id: route.query_id().into(),
            gate: route.gate().into(),
            params: route.extra().borrow().to_string(),
        }
    }

    pub fn into<T: DeserializeOwned>(self) -> T {
        serde_json::from_str(&self.params).unwrap()
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

impl<I: Debug> Debug for Addr<I> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Addr[route={:?}, from={:?}, query_id={:?}, step={:?}, params={}]",
            self.route, self.origin, self.query_id, self.gate, self.params
        )
    }
}
