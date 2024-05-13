use axum::{extract::Path, routing::get, Extension, Json, Router};
use hyper::StatusCode;

use crate::{
    helpers::{BodyStream, Transport},
    net::{
        http_serde::query::status::{self, Request},
        server::Error,
        HttpTransport,
    },
    protocol::QueryId,
    sync::Arc,
};

async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    Path(query_id): Path<QueryId>,
) -> Result<Json<status::ResponseBody>, Error> {
    let req = Request { query_id };
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
    use axum::http::uri::{Authority, Scheme};
    use hyper::{Body, StatusCode};

    use crate::{
        helpers::{
            make_owned_handler,
            routing::{Addr, RouteId},
            BodyStream, HelperIdentity, HelperResponse,
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{assert_fails_with, assert_success_with},
        },
        protocol::QueryId,
        query::QueryStatus,
    };

    #[tokio::test]
    async fn status_test() {
        let expected_status = QueryStatus::Running;
        let expected_query_id = QueryId;

        let handler = make_owned_handler(
            move |addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                let RouteId::QueryStatus = addr.route else {
                    panic!("unexpected call");
                };
                assert_eq!(addr.query_id, Some(expected_query_id));
                Ok(HelperResponse::from(expected_status))
            },
        );

        let req = http_serde::query::status::Request::new(QueryId);
        let req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        assert_success_with(req, handler).await;
    }

    struct OverrideReq {
        query_id: String,
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{}/{}",
                http_serde::query::BASE_AXUM_PATH,
                val.query_id
            );
            hyper::Request::get(uri).body(hyper::Body::empty()).unwrap()
        }
    }

    #[tokio::test]
    async fn malformed_query_id() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
        };

        assert_fails_with(req.into(), StatusCode::BAD_REQUEST).await;
    }
}
