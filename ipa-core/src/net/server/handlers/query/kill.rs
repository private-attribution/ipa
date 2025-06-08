use axum::{Extension, Json, Router, extract::Path, routing::post};
use hyper::StatusCode;

use crate::{
    helpers::{ApiError, BodyStream},
    net::{
        Error::QueryIdNotFound,
        http_serde::query::kill::{self, Request},
        server::Error,
        transport::MpcHttpTransport,
    },
    protocol::QueryId,
    query::QueryKillStatus,
};

async fn handler(
    transport: Extension<MpcHttpTransport>,
    Path(query_id): Path<QueryId>,
) -> Result<Json<kill::ResponseBody>, Error> {
    let req = Request { query_id };
    match transport.dispatch(req, BodyStream::empty()).await {
        Ok(state) => Ok(Json(kill::ResponseBody::from(state))),
        Err(ApiError::QueryKill(QueryKillStatus::NoSuchQuery(query_id))) => Err(
            Error::application(StatusCode::NOT_FOUND, QueryIdNotFound(query_id)),
        ),
        Err(e) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub fn router(transport: MpcHttpTransport) -> Router {
    Router::new()
        .route(kill::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use axum::{
        body::Body,
        http::uri::{Authority, Scheme},
    };
    use hyper::StatusCode;

    use crate::{
        helpers::{
            ApiError, BodyStream, HelperIdentity, HelperResponse, make_owned_handler,
            routing::{Addr, RouteId},
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{
                assert_fails_with, assert_fails_with_handler, assert_success_with,
            },
        },
        protocol::QueryId,
        query::{QueryKillStatus, QueryKilled},
    };

    #[tokio::test]
    async fn calls_kill() {
        let expected_query_id = QueryId;

        let handler = make_owned_handler(
            move |addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                let RouteId::KillQuery = addr.route else {
                    panic!("unexpected call: {addr:?}");
                };
                assert_eq!(addr.query_id, Some(expected_query_id));
                Ok(HelperResponse::from(QueryKilled(expected_query_id)))
            },
        );

        let req = http_serde::query::kill::Request::new(QueryId);
        let req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        assert_success_with(req, handler).await;
    }

    #[tokio::test]
    async fn no_such_query() {
        let handler = make_owned_handler(
            move |_addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                Err(QueryKillStatus::NoSuchQuery(QueryId).into())
            },
        );

        let req = http_serde::query::kill::Request::new(QueryId)
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        assert_fails_with_handler(req, handler, StatusCode::NOT_FOUND).await;
    }

    #[tokio::test]
    async fn unknown_error() {
        let handler = make_owned_handler(
            move |_addr: Addr<HelperIdentity>, _data: BodyStream| async move {
                Err(ApiError::DeserializationFailure(
                    serde_json::from_str::<()>("not-a-json").unwrap_err(),
                ))
            },
        );

        let req = http_serde::query::kill::Request::new(QueryId)
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        assert_fails_with_handler(req, handler, StatusCode::INTERNAL_SERVER_ERROR).await;
    }

    struct OverrideReq {
        query_id: String,
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{}/{}/kill",
                http_serde::query::BASE_AXUM_PATH,
                val.query_id
            );
            hyper::Request::post(uri).body(Body::empty()).unwrap()
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
