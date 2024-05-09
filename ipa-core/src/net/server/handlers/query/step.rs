use axum::{extract::Path, routing::post, Extension, Router};

use crate::{
    helpers::{BodyStream, Transport},
    net::{
        http_serde,
        server::{ClientIdentity, Error},
        HttpTransport,
    },
    protocol::{step::Gate, QueryId},
    sync::Arc,
};

#[allow(clippy::unused_async)] // axum doesn't like synchronous handler
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    from: Extension<ClientIdentity>,
    Path((query_id, gate)): Path<(QueryId, Gate)>,
    body: BodyStream,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    transport.receive_stream(query_id, gate, **from, body);
    Ok(())
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::step::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::task::Poll;

    use futures::{stream::poll_immediate, StreamExt};
    use hyper::{Body, StatusCode};

    use super::*;
    use crate::{
        helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{
            server::handlers::query::test_helpers::{assert_fails_with, MaybeExtensionExt},
            test::TestServer,
        },
        protocol::{
            step::{Gate, StepNarrow},
            QueryId,
        },
    };

    const DATA_LEN: usize = 3;

    #[tokio::test]
    async fn step() {
        let payload = vec![213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];
        let req: OverrideReq = OverrideReq {
            payload: payload.clone(),
            client_id: Some(ClientIdentity(HelperIdentity::TWO)),
            ..Default::default()
        };
        let test_server = TestServer::builder().build().await;

        let step = Gate::default().narrow("test");

        test_server.server.handle_req(req.into()).await;

        let mut stream = Arc::clone(&test_server.transport)
            .receive(HelperIdentity::TWO, (QueryId, step))
            .into_bytes_stream();

        assert_eq!(
            poll_immediate(&mut stream).next().await,
            Some(Poll::Ready(payload))
        );
    }

    struct OverrideReq {
        client_id: Option<ClientIdentity>,
        query_id: String,
        gate: Gate,
        payload: Vec<u8>,
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{}/{}/step/{}",
                http_serde::query::BASE_AXUM_PATH,
                val.query_id,
                val.gate.as_ref()
            );
            hyper::Request::post(uri)
                .maybe_extension(val.client_id)
                .body(hyper::Body::from(val.payload))
                .unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                client_id: Some(ClientIdentity(HelperIdentity::ONE)),
                query_id: QueryId.as_ref().to_string(),
                gate: Gate::default().narrow("test"),
                payload: vec![1; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES],
            }
        }
    }

    #[tokio::test]
    async fn malformed_query_id_fails() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn auth_required() {
        let req = OverrideReq {
            client_id: None,
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNAUTHORIZED).await;
    }
}
