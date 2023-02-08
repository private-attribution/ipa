use crate::{
    helpers::{transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::{routing::post, Extension, Router};
use std::collections::HashMap;
use tokio::sync::mpsc;

type OngoingQueries = Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>;

#[allow(clippy::type_complexity)] // it's a hashmap
async fn handler(
    req: http_serde::query::step::Request,
    ongoing_queries: Extension<OngoingQueries>,
) -> Result<(), Error> {
    // wrap in braces to ensure lock is released
    let network_sender = {
        ongoing_queries
            .lock()
            .unwrap()
            .get(&req.query_id)
            .ok_or_else(|| Error::QueryIdNotFound(req.query_id))?
            .clone()
    };
    let permit = network_sender.reserve().await?;

    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(req.origin),
        payload: TransportCommand::StepData {
            query_id: req.query_id,
            step: req.step,
            payload: req.payload,
            offset: req.offset,
        },
    };
    permit.send(command);
    Ok(())
}

pub fn router(ongoing_queries: OngoingQueries) -> Router {
    Router::new()
        .route(http_serde::query::step::AXUM_PATH, post(handler))
        .layer(Extension(ongoing_queries))
}

#[cfg(all(test, not(feature = "shuttle")))]
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

#[cfg(all(test, not(feature = "shuttle")))]
mod e2e_tests {
    use super::*;
    use crate::{
        helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::MpcHelperServer,
        protocol::Step,
    };
    use futures::future::poll_immediate;
    use hyper::{http::uri, service::Service, StatusCode};
    use tower::ServiceExt;

    #[tokio::test]
    async fn backpressure_applied() {
        const QUEUE_DEPTH: usize = 8;
        let (management_tx, _) = mpsc::channel(1);
        let (query_tx, mut query_rx) = mpsc::channel(QUEUE_DEPTH);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::from([(QueryId, query_tx)])));
        let server = MpcHelperServer::new(management_tx, ongoing_queries);
        let mut r = server.router();

        // prepare req
        let mut offset = 0;
        let mut new_req = || {
            let req = http_serde::query::step::Request::new(
                HelperIdentity::try_from(1).unwrap(),
                QueryId,
                Step::default().narrow("test"),
                vec![0; 3 * MESSAGE_PAYLOAD_SIZE_BYTES],
                offset,
            );
            offset += 1;
            req.try_into_http_request(
                uri::Scheme::HTTP,
                uri::Authority::from_static("example.com"),
            )
            .unwrap()
        };

        // fill channel
        for _ in 0..QUEUE_DEPTH {
            let resp = r.ready().await.unwrap().call(new_req()).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "body: {}",
                String::from_utf8_lossy(&hyper::body::to_bytes(resp.into_body()).await.unwrap())
            );
        }

        // channel should now be full
        let mut resp_when_full = r.ready().await.unwrap().call(new_req());
        assert!(
            matches!(poll_immediate(&mut resp_when_full).await, None),
            "expected future to be pending"
        );

        // take 1 message from channel
        query_rx.recv().await;

        // channel should now have capacity
        assert!(poll_immediate(&mut resp_when_full).await.is_some());

        // take 3 messages from channel
        for _ in 0..3 {
            query_rx.recv().await;
        }

        // channel should now have capacity for 3 more reqs
        for _ in 0..3 {
            let mut next_req = r.ready().await.unwrap().call(new_req());
            assert!(poll_immediate(&mut next_req).await.is_some());
        }

        // channel should have no more capacity
        let mut resp_when_full = r.ready().await.unwrap().call(new_req());
        assert!(matches!(poll_immediate(&mut resp_when_full).await, None));
    }
}
