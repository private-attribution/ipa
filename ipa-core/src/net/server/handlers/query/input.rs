use axum::{routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{routing::RouteId, Transport},
    net::{http_serde, Error, HttpTransport},
    sync::Arc,
};

async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::input::Request,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    let _ = transport
        .dispatch(
            (RouteId::QueryInput, req.query_input.query_id),
            req.query_input.input_stream,
        )
        .await
        .map_err(|e| Error::application(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(())
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::input::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {

    use axum::{http::Request, Extension};
    use hyper::{Body, StatusCode};
    use tokio::runtime::Handle;

    use crate::{
        helpers::{
            make_owned_handler, query::QueryInput, routing::RouteId, BytesStream, HelperResponse,
        },
        net::{
            http_serde,
            server::handlers::query::{
                input::handler,
                test_helpers::{assert_req_fails_with, IntoFailingReq},
            },
            test::TestServer,
        },
        protocol::QueryId,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn input_test() {
        let expected_query_id = QueryId;
        let expected_input = &[4u8; 4];
        let req_handler = make_owned_handler(move |addr, data| async move {
            let RouteId::QueryInput = addr.route else {
                panic!("unexpected call");
            };

            assert_eq!(addr.query_id, Some(expected_query_id));
            assert_eq!(
                tokio::task::block_in_place(move || {
                    Handle::current().block_on(async move { data.to_vec().await })
                }),
                expected_input
            );

            Ok(HelperResponse::ok())
        });

        let test_server = TestServer::builder()
            .with_request_handler(req_handler)
            .build()
            .await;
        let req = http_serde::query::input::Request::new(QueryInput {
            query_id: expected_query_id,
            input_stream: expected_input.to_vec().into(),
        });
        handler(Extension(test_server.transport), req)
            .await
            .unwrap();
    }

    struct OverrideReq {
        query_id: String,
        input_stream: Vec<u8>,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://localhost:{}{}/{}/input",
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
