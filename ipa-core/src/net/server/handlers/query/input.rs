use axum::{extract::Path, routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{query::QueryInputRequest, BodyStream},
    net::{http_serde::{self, query::input::QueryInputUrl}, transport::MpcHttpTransport, Error},
    protocol::QueryId,
};

async fn handler(
    transport: Extension<MpcHttpTransport>,
    Path(query_id): Path<QueryId>,
    input_url: QueryInputUrl,
    input_stream: BodyStream,
) -> Result<(), Error> {
    let query_input = if let Some(url) = input_url.into() {
        QueryInputRequest::FromUrl { query_id, url }
    } else {
        QueryInputRequest::Inline { query_id }
    };
    let _ = transport
        .dispatch(query_input, input_stream)
        .await
        .map_err(|e| Error::application(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(())
}

pub fn router(transport: MpcHttpTransport) -> Router {
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
    async fn input_inline() {
        let expected_query_id = QueryId;
        let expected_input = &[4u8; 4];
        let req = http_serde::query::input::Request::new(QueryInput::Inline {
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

    #[tokio::test(flavor = "multi_thread")]
    async fn input_from_url() {
        let expected_query_id = QueryId;
        let expected_url = "https://storage.example/ipa-reports";
        let req = http_serde::query::input::Request::new(QueryInput::FromUrl {
            query_id: expected_query_id,
            url: expected_url.parse().unwrap(),
        });
        let req_handler = make_owned_handler(move |addr, _body| async move {
            let RouteId::QueryInput = addr.route else {
                panic!("unexpected call");
            };

            assert_eq!(addr.query_id, Some(expected_query_id));
            assert_eq!(addr.params, expected_url);

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
