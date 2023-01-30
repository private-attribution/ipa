use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::get, Extension, Router};
use tokio::sync::{mpsc, oneshot};

/// Handles the completion of the query by blocking the sender until query is completed.
async fn handler(
    req: http_serde::query::results::Request,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
) -> Result<Vec<u8>, Error> {
    let permit = transport_sender.reserve().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();

    // send command, receive response
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Results(req.query_id, tx)),
    };
    permit.send(command);
    let results = rx.await?;

    Ok(results.into_bytes())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::results::AXUM_PATH, get(handler))
        .layer(Extension(transport_sender))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::Fp31,
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::QueryId,
        query::ProtocolResult,
        secret_sharing::replicated::semi_honest::AdditiveShare as Replicated,
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
