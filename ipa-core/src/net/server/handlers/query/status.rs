use axum::{routing::get, Extension, Json, Router};
use hyper::StatusCode;

use crate::{
    helpers::{BodyStream, Transport},
    net::{http_serde::query::status, server::Error, HttpTransport},
    sync::Arc,
};

async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: status::Request,
) -> Result<Json<status::ResponseBody>, Error> {
    let transport = Transport::clone_ref(&*transport);
    match transport.dispatch(req, BodyStream::empty()).await {
        Ok(state) => Ok(Json(status::ResponseBody::from(state))),
        Err(e) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(status::AXUM_PATH, get(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {

    use axum::{http::Request, Extension, Json};
    use hyper::StatusCode;

    use crate::{
        helpers::{
            make_owned_handler,
            routing::{Addr, RouteId},
            BodyStream, HelperIdentity, HelperResponse,
        },
        net::{
            http_serde,
            server::handlers::query::{
                status::handler,
                test_helpers::{assert_req_fails_with, IntoFailingReq},
            },
            test::TestServer,
        },
        protocol::QueryId,
        query::QueryStatus,
    };

    #[tokio::test]
    async fn status_test() {
        let expected_status = QueryStatus::Running;
        let expected_query_id = QueryId;
        let test_server = TestServer::builder()
            .with_request_handler(make_owned_handler(
                move |addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                    let RouteId::QueryStatus = addr.route else {
                        panic!("unexpected call");
                    };
                    assert_eq!(addr.query_id, Some(expected_query_id));
                    Ok(HelperResponse::from(expected_status))
                },
            ))
            .build()
            .await;
        let req = http_serde::query::status::Request::new(QueryId);
        let response = handler(Extension(test_server.transport), req.clone())
            .await
            .unwrap();

        let Json(http_serde::query::status::ResponseBody { status }) = response;
        assert_eq!(status, expected_status);
    }

    struct OverrideReq {
        query_id: String,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<hyper::Body> {
            let uri = format!(
                "http://localhost:{}{}/{}",
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
