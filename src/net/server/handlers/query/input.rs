use crate::{
    helpers::Transport,
    net::{http_serde, Error, HttpTransport},
    sync::Arc,
};
use axum::{routing::post, Extension, Router};
use hyper::StatusCode;

async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::input::Request,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    transport
        .query_input(req.query_input)
        .await
        .map_err(|e| Error::application(StatusCode::INTERNAL_SERVER_ERROR, e))
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::input::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        helpers::query::QueryInput,
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::QueryId,
    };
    use axum::http::Request;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
    use hyper::{Body, StatusCode};
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn input_test() {
        let expected_query_id = QueryId;
        let expected_input = vec![4u8; 4];
        let req = http_serde::query::input::Request::new(QueryInput {
            query_id: expected_query_id,
            input_stream: expected_input.clone().into(),
        });
        let (tx, mut rx) = mpsc::channel(1);
        let handle = handler(req, Extension(tx));
        pin_mut!(handle);
        // should be pending while waiting for `rx`
        assert!(matches!(poll_immediate(&mut handle).await, None));
        let res = poll_immediate(rx.recv()).await.unwrap().unwrap();
        assert_eq!(res.origin, CommandOrigin::Other);
        match res.payload {
            TransportCommand::Query(QueryCommand::Input(
                QueryInput {
                    query_id,
                    input_stream,
                },
                responder,
            )) => {
                assert_eq!(query_id, expected_query_id);
                let input = input_stream.to_vec().await;
                assert_eq!(input, expected_input);
                responder.send(()).unwrap();
            }
            other => panic!("expected input command, but got {other:?}"),
        }

        poll_immediate(handle).await.unwrap().unwrap();
    }

    struct OverrideReq {
        query_id: String,
        input_stream: Vec<u8>,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://127.0.0.1:{}{}/input?query_id={}",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id
            );
            hyper::Request::post(uri)
                .body(hyper::Body::from(self.input_stream))
                .unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                query_id: QueryId.as_ref().to_string(),
                input_stream: vec![4; 4],
            }
        }
    }

    #[tokio::test]
    async fn malformed_query_id() {
        let req = OverrideReq {
            query_id: "not_a_query_id".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
