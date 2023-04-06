use crate::{
    helpers::Transport,
    net::{http_serde, server::Error, HttpTransport},
    sync::Arc,
};
use axum::{extract::BodyStream, routing::post, Extension, Router};

#[allow(clippy::unused_async)] // axum doesn't like synchronous handler
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::step::Request<BodyStream>,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    transport.receive_stream(req.query_id, req.step, req.origin, req.body);
    Ok(())
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::step::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, not(feature = "shuttle")))]
#[cfg(never)]
mod tests {
    use super::*;
    use crate::{
        helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::Step,
    };
    use axum::http::Request;
    use futures_util::future::poll_immediate;
    use hyper::{Body, StatusCode};

    const DATA_LEN: usize = 3;

    #[allow(clippy::type_complexity)] // it's a hashmap
    fn filled_ongoing_queries() -> (
        Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
        mpsc::Receiver<CommandEnvelope>,
    ) {
        let (tx, rx) = mpsc::channel(1);
        (Arc::new(Mutex::new(HashMap::from([(QueryId, tx)]))), rx)
    }

    #[tokio::test]
    async fn collect_req() {
        for offset in 0..10 {
            let req = http_serde::query::step::Request::new(
                HelperIdentity::try_from(2).unwrap(),
                QueryId,
                Step::default().narrow("test"),
                vec![213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES],
                offset,
            );

            let (ongoing_queries, mut rx) = filled_ongoing_queries();

            poll_immediate(handler(req.clone(), Extension(ongoing_queries)))
                .await
                .unwrap()
                .expect("request should succeed");
            let res = poll_immediate(rx.recv()).await.unwrap().unwrap();

            assert_eq!(res.origin, CommandOrigin::Helper(req.origin));
            match res.payload {
                TransportCommand::StepData {
                    query_id,
                    step,
                    payload,
                    offset,
                } => {
                    assert_eq!(req.query_id, query_id);
                    assert_eq!(req.step, step);
                    assert_eq!(req.payload, payload);
                    assert_eq!(req.offset, offset);
                }
                other @ TransportCommand::Query(_) => {
                    panic!("expected command to be `StepData`, but found {other:?}")
                }
            }
        }
    }

    struct OverrideReq {
        origin: u8,
        query_id: String,
        step: Step,
        payload: Vec<u8>,
        offset: u32,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://localhost:{}{}/{}/step/{}",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id,
                self.step.as_ref()
            );
            hyper::Request::post(uri)
                .header("offset", self.offset)
                .header("origin", u32::from(self.origin))
                .body(hyper::Body::from(self.payload))
                .unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                origin: 1,
                query_id: QueryId.as_ref().to_string(),
                step: Step::default().narrow("test"),
                payload: vec![1; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES],
                offset: 0,
            }
        }
    }

    #[tokio::test]
    async fn malformed_origin_fails() {
        let req = OverrideReq {
            origin: 4,
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn malformed_query_id_fails() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn wrong_payload_size_is_rejected() {
        let req = OverrideReq {
            payload: vec![0; MESSAGE_PAYLOAD_SIZE_BYTES + 1],
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_payload_fails() {
        let req = OverrideReq {
            payload: vec![0, 7],
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
