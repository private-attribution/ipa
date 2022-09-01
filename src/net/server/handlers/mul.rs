use crate::field::Field;
use crate::net::server::MpcServerError;
use crate::protocol::{QueryId, Step};
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use crate::{helpers, helpers::http::Controller, helpers::Identity};
use axum::body::Bytes;
use axum::extract::{Path, Query};
use futures::Stream;
use futures_util::{future, TryStreamExt};
use hyper::Body;

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct QueryParams {
    identity: Identity,
}

pub struct Handler<S, St> {
    controller: Controller<S, St>,
}

impl<S, F, St> Handler<S, St>
where
    S: Step,
    F: Field,
    St: Stream<Item = helpers::Result<ReplicatedSecretSharing<F>>>,
{
    pub fn new(controller: Controller<S, St>) -> Self {
        Handler { controller }
    }

    /// handles POST requests of the shape: `/mul/query_id/:query_id/step/*step?identity=[H1,H2,H3]`
    pub async fn handler(
        &self,
        Path((_query_id, step)): Path<(QueryId, S)>,
        Query(QueryParams { identity }): Query<QueryParams>,
        body: Body,
    ) -> Result<(), MpcServerError> {
        println!("{_query_id:?}, {step:?}");
        // let body: St = body.map_err(helpers::Error::from).and_then(|b| {
        //     let res: Result<ReplicatedSecretSharing<F>, serde_json::Error> =
        //         serde_json::from_slice(&b);
        //     future::ready(res.map_err(helpers::Error::from))
        // });
        // let body: St = body
        //     .map_err(helpers::Error::from)
        //     .and_then(|b| future::ready(serde_json::from_slice(&b).map_err(helpers::Error::from)));
        let body: St = Self::b(Self::a(body));
        self.controller.add_incoming(identity, step, body);
        Ok(())
    }

    fn a(body: Body) -> impl Stream<Item = helpers::Result<Bytes>> {
        body.map_err(helpers::Error::from)
    }
    fn b<St1: Stream<Item = helpers::Result<Bytes>>>(n: St1) -> St {
        n.and_then(|b| future::ready(serde_json::from_slice(&b).map_err(helpers::Error::from)))
    }
}
