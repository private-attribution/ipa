use std::sync::Arc;

use axum::{routing::get, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::Transport,
    net::{http_serde, server::Error, HttpTransport},
};

/// Handles the completion of the query by blocking the sender until query is completed.
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::results::Request,
) -> Result<Vec<u8>, Error> {
    // TODO: we may be able to stream the response
    let transport = Transport::clone_ref(&*transport);
    match transport.complete_query(req.query_id).await {
        Ok(result) => Ok(result.into_bytes()),
        Err(e) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::results::AXUM_PATH, get(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::future::ready;

    use axum::http::Request;
    use hyper::StatusCode;

    use super::*;
    use crate::{
        ff::Fp31,
        helpers::TransportCallbacks,
        net::{
            server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
            test::TestServer,
        },
        protocol::QueryId,
        query::ProtocolResult,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
    };

    #[tokio::test]
    async fn results_test() {
        let expected_results = Box::new(vec![Replicated::from((
            Fp31::try_from(1u128).unwrap(),
            Fp31::try_from(2u128).unwrap(),
        ))]);
        let expected_query_id = QueryId;
        let raw_results = expected_results.to_vec();
        let cb = TransportCallbacks {
            complete_query: Box::new(move |_transport, query_id| {
                let results: Box<dyn ProtocolResult> = Box::new(raw_results.clone());
                assert_eq!(query_id, expected_query_id);
                Box::pin(ready(Ok(results)))
            }),
            ..Default::default()
        };
        let TestServer { transport, .. } = TestServer::builder().with_callbacks(cb).build().await;
        let req = http_serde::query::results::Request::new(QueryId);
        let results = handler(Extension(transport), req.clone()).await.unwrap();
        assert_eq!(results, expected_results.into_bytes());
    }

    struct OverrideReq {
        query_id: String,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<hyper::Body> {
            let uri = format!(
                "http://localhost:{}{}/{}/complete",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id
            );
            hyper::Request::get(uri).body(hyper::Body::empty()).unwrap()
        }
    }

    #[tokio::test]
    async fn malformed_query_id() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
        };

        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
