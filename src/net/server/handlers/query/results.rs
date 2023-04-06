use std::sync::Arc;

use crate::{
    helpers::Transport,
    net::{http_serde, server::Error, HttpTransport},
};
use axum::{routing::get, Extension, Router};
use hyper::StatusCode;

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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::Fp31,
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::QueryId,
        query::ProtocolResult,
        secret_sharing::replicated::{
            semi_honest::AdditiveShare as Replicated, ReplicatedSecretSharing,
        },
    };
    use axum::http::Request;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use hyper::StatusCode;

    #[tokio::test]
    async fn results_test() {
        let req = http_serde::query::results::Request::new(QueryId);
        let (tx, mut rx) = mpsc::channel(1);
        let handle = handler(req.clone(), Extension(tx));
        pin_mut!(handle);

        // should be pending while waiting for `rx`
        assert!(matches!(poll_immediate(&mut handle).await, None));
        let res = poll_immediate(rx.recv()).await.unwrap().unwrap();
        assert_eq!(res.origin, CommandOrigin::Other);

        let expected_resp = vec![Replicated::new(Fp31::from(1u128), Fp31::from(2u128))];
        match res.payload {
            TransportCommand::Query(QueryCommand::Results(query_id, responder)) => {
                assert_eq!(query_id, req.query_id);
                responder
                    .send(Box::new(expected_resp.clone()) as Box<dyn ProtocolResult>)
                    .unwrap();
            }
            other => panic!("expected create command, but got {other:?}"),
        }
        let resp_bytes = poll_immediate(handle).await.unwrap().unwrap();
        let resp = Replicated::<Fp31>::from_byte_slice(&resp_bytes).collect::<Vec<_>>();
        assert_eq!(resp, expected_resp);
    }

    struct OverrideReq {
        query_id: String,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<hyper::Body> {
            let uri = format!(
                "http://127.0.0.1:{}{}/{}/complete",
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
