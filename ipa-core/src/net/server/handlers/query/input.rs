use axum::{extract::Path, routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{query::QueryInput, routing::RouteId, BodyStream, Transport},
    net::{http_serde, Error, HttpTransport},
    protocol::QueryId,
    sync::Arc,
};

async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    Path(query_id): Path<QueryId>,
    input_stream: BodyStream,
) -> Result<(), Error> {
    let query_input = QueryInput {
        query_id,
        input_stream,
    };
    let transport = Transport::clone_ref(&*transport);
    let _ = transport
        .dispatch(
            (RouteId::QueryInput, query_input.query_id),
            query_input.input_stream,
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
    use axum::{
        body::Body,
        http::uri::{Authority, Scheme},
    };
    use hyper::StatusCode;
    use tokio::runtime::Handle;

    use crate::{
        helpers::{
            make_owned_handler, query::QueryInput, routing::RouteId, BytesStream, HelperResponse,
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{assert_fails_with, assert_success_with},
        },
        protocol::QueryId,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn input_test() {
        let expected_query_id = QueryId;
        let expected_input = &[4u8; 4];
        let req = http_serde::query::input::Request::new(QueryInput {
            query_id: expected_query_id,
            input_stream: expected_input.to_vec().into(),
        });
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
        let req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        assert_success_with(req, req_handler).await;
    }

    struct OverrideReq {
        query_id: String,
        input_stream: Vec<u8>,
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{}/{}/input",
                http_serde::query::BASE_AXUM_PATH,
                val.query_id
            );
            hyper::Request::post(uri)
                .body(Body::from(val.input_stream))
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
        assert_fails_with(req.into(), StatusCode::BAD_REQUEST).await;
    }
}
