use axum::{routing::post, Extension, Router};

use crate::{
    helpers::{BodyStream, Transport},
    net::{
        http_serde,
        server::{ClientIdentity, Error},
        HttpTransport,
    },
    sync::Arc,
};

#[allow(clippy::unused_async)] // axum doesn't like synchronous handler
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    from: Extension<ClientIdentity>,
    req: http_serde::query::step::Request<BodyStream>,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    transport.receive_stream(req.query_id, req.gate, **from, req.body);
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

    use axum::http::Request;
    use futures::{stream::poll_immediate, StreamExt};
    use hyper::{Body, StatusCode};

    use super::*;
    use crate::{
        helpers::{HelperIdentity, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{
            server::handlers::query::{
                test_helpers::{assert_req_fails_with, IntoFailingReq},
                MaybeExtensionExt,
            },
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
        let TestServer { transport, .. } = TestServer::builder().build().await;

        let step = Gate::default().narrow("test");
        let payload = vec![213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];
        let req =
            http_serde::query::step::Request::new(QueryId, step.clone(), payload.clone().into());

        handler(
            Extension(Arc::clone(&transport)),
            Extension(ClientIdentity(HelperIdentity::TWO)),
            req,
        )
        .await
        .unwrap();

        let mut stream = Arc::clone(&transport)
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

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://localhost:{}{}/{}/step/{}",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id,
                self.gate.as_ref()
            );
            hyper::Request::post(uri)
                .maybe_extension(self.client_id)
                .body(hyper::Body::from(self.payload))
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
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn auth_required() {
        let req = OverrideReq {
            client_id: None,
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNAUTHORIZED).await;
    }
}
