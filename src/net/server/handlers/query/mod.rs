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

#[cfg(test)]
pub mod test_helpers {
    use crate::net::server::BindTarget;
    use crate::net::MpcHelperServer;
    use crate::protocol::QueryId;
    use crate::sync::{Arc, Mutex};
    use futures_util::FutureExt;
    use hyper::StatusCode;
    use std::collections::HashMap;
    use std::future::Future;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;

    pub trait IntoReq: Default {
        fn into_req(self, port: u16) -> hyper::Request<hyper::Body>;
    }

    pub async fn init_server(query_id: QueryId) -> u16 {
        let (management_tx, _) = mpsc::channel(1);
        let (query_tx, _query_rx) = mpsc::channel(1);
        let ongoing_queries = HashMap::from([(query_id, query_tx)]);
        let server = MpcHelperServer::new(management_tx, Arc::new(Mutex::new(ongoing_queries)));
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        addr.port()
    }

    pub async fn resp_eq<I: IntoReq>(req: I, expected_status: StatusCode) {
        let port = init_server(QueryId).await;
        let resp = hyper::Client::default()
            .request(req.into_req(port))
            .await
            .expect("request should complete successfully");
        assert_eq!(resp.status(), expected_status);
    }

    pub fn poll_immediate<F, T>(f: &mut F) -> Poll<T>
    where
        F: Future<Output = T> + Unpin,
    {
        f.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref()))
    }
}
