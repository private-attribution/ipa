mod create;
mod input;
mod prepare;
mod results;
mod step;

use crate::{
    helpers::CommandEnvelope,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::Router;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub fn router(
    transport_sender: mpsc::Sender<CommandEnvelope>,
    // TODO: clean up after query has been processed
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    Router::new()
        .merge(create::router(transport_sender.clone()))
        .merge(prepare::router(transport_sender.clone()))
        .merge(input::router(transport_sender.clone()))
        .merge(results::router(transport_sender))
        .merge(step::router(ongoing_queries))
}

#[cfg(all(test, not(feature = "shuttle")))]
pub mod test_helpers {
    use crate::{
        net::MpcHelperServer,
        protocol::QueryId,
        sync::{Arc, Mutex},
    };
    use futures_util::future::poll_immediate;
    use hyper::{service::Service, StatusCode};
    use std::collections::HashMap;
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    /// types that implement `IntoFailingReq` are intended to induce some failure in the process of
    /// axum routing. Pair with `assert_req_fails_with` to detect specific [`StatusCode`] failures.
    pub trait IntoFailingReq {
        fn into_req(self, port: u16) -> hyper::Request<hyper::Body>;
    }

    /// Intended to be used for a request that will fail during axum routing. When passed a known
    /// bad request via `IntoFailingReq`, get a response from the server, and compare its
    /// [`StatusCode`] with what is expected.
    pub async fn assert_req_fails_with<I: IntoFailingReq>(req: I, expected_status: StatusCode) {
        let (management_tx, _management_rx) = mpsc::channel(1);
        let (query_tx, _query_rx) = mpsc::channel(1);
        let ongoing_queries = HashMap::from([(QueryId, query_tx)]);
        let server = MpcHelperServer::new(management_tx, Arc::new(Mutex::new(ongoing_queries)));

        let mut router = server.router();
        let ready = poll_immediate(router.ready()).await.unwrap().unwrap();
        let resp = poll_immediate(ready.call(req.into_req(0)))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(resp.status(), expected_status);
    }
}
