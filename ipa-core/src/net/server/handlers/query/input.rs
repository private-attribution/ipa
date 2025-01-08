use axum::{extract::Path, routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{routing::RouteId, BodyStream},
    net::{
        http_serde::{self, query::input::QueryInputUrl},
        query_input::stream_query_input_from_url,
        transport::MpcHttpTransport,
        Error,
    },
    protocol::QueryId,
};

async fn handler(
    transport: Extension<MpcHttpTransport>,
    Path(query_id): Path<QueryId>,
    input_url: QueryInputUrl,
    input_stream: BodyStream,
) -> Result<(), Error> {
    let input_stream = if let Some(url) = input_url.into() {
        stream_query_input_from_url(&url).await?
    } else {
        input_stream
    };
    let _ = transport
        .dispatch((RouteId::QueryInput, query_id), input_stream)
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
    use std::thread;

    use axum::{
        body::Body,
        http::uri::{Authority, Scheme},
    };
    use bytes::BytesMut;
    use futures::TryStreamExt;
    use http_body_util::BodyExt;
    use hyper::StatusCode;
    use tokio::runtime::Handle;

    use crate::{
        helpers::{
            make_owned_handler, query::QueryInput, routing::RouteId, BytesStream, HelperResponse,
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{assert_fails_with, assert_success_with},
            test::TestServer,
        },
        protocol::QueryId,
    };

    #[tokio::test(flavor = "multi_thread")]
    async fn input_inline() {
        const QUERY_ID: QueryId = QueryId;
        let expected_input = &[4u8; 4];

        let req_handler = make_owned_handler(move |addr, data| async move {
            let RouteId::QueryInput = addr.route else {
                panic!("unexpected call");
            };

            assert_eq!(addr.query_id, Some(QUERY_ID));
            assert_eq!(
                tokio::task::block_in_place(move || {
                    Handle::current().block_on(async move { data.to_vec().await })
                }),
                expected_input
            );

            Ok(HelperResponse::ok())
        });

        let req = http_serde::query::input::Request::new(QueryInput::Inline {
            query_id: QUERY_ID,
            input_stream: expected_input.to_vec().into(),
        });
        let hyper_req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();

        assert_success_with(hyper_req, req_handler).await;
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn input_from_url() {
        const QUERY_ID: QueryId = QueryId;
        const DATA: &str = "<input records>";

        let server = tiny_http::Server::http("localhost:0").unwrap();
        let addr = server.server_addr();
        thread::spawn(move || {
            let request = server.recv().unwrap();
            let response = tiny_http::Response::from_string(DATA);
            request.respond(response).unwrap();
        });

        let req_handler = make_owned_handler(move |addr, body| async move {
            let RouteId::QueryInput = addr.route else {
                panic!("unexpected call");
            };

            assert_eq!(addr.query_id, Some(QUERY_ID));
            assert_eq!(body.try_collect::<BytesMut>().await.unwrap(), DATA);

            Ok(HelperResponse::ok())
        });
        let test_server = TestServer::builder()
            .with_request_handler(req_handler)
            .build()
            .await;

        let url = format!(
            "http://localhost:{}/input-data",
            addr.to_ip().unwrap().port(),
        );
        let req = http_serde::query::input::Request::new(QueryInput::FromUrl {
            query_id: QUERY_ID,
            url,
        });
        let hyper_req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();

        let resp = test_server.server.handle_req(hyper_req).await;
        if !resp.status().is_success() {
            let (head, body) = resp.into_parts();
            let body_bytes = body.collect().await.unwrap().to_bytes();
            let body = String::from_utf8_lossy(&body_bytes);
            panic!("{head:?}\n{body}");
        }
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
