use std::sync::Arc;

use crate::{
    net::{http_serde, HttpTransport},
    query::PrepareQueryError,
};
use axum::{response::IntoResponse, routing::post, Extension, Router};
use hyper::StatusCode;

/// Called by whichever peer helper is the leader for an individual query, to initiatialize
/// processing of that query.
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::prepare::Request,
) -> Result<(), PrepareQueryError> {
    Arc::clone(&transport).prepare_query(req.data).await
}

impl IntoResponse for PrepareQueryError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::BAD_REQUEST, self.to_string()).into_response()
    }
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::prepare::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use std::future::ready;

    use super::*;
    use crate::{
        ff::FieldType,
        helpers::{
            query::{PrepareQuery, QueryConfig, QueryType},
            HelperIdentity, RoleAssignment, TransportCallbacks,
        },
        net::{
            server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
            test::TestServer,
        },
        protocol::QueryId,
    };
    use axum::http::Request;
    use hyper::{Body, StatusCode};

    #[tokio::test]
    async fn prepare_test() {
        let req = http_serde::query::prepare::Request::new(
            HelperIdentity::try_from(2).unwrap(),
            PrepareQuery {
                query_id: QueryId,
                config: QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                },
                roles: RoleAssignment::new(HelperIdentity::make_three()),
            },
        );
        let expected_prepare_query = req.data.clone();

        let cb = TransportCallbacks {
            prepare_query: Box::new(move |_transport, prepare_query| {
                assert_eq!(prepare_query, expected_prepare_query);
                Box::pin(ready(Ok(())))
            }),
            ..Default::default()
        };
        let TestServer { transport, .. } = TestServer::builder().with_callbacks(cb).build().await;
        handler(Extension(transport), req.clone()).await.unwrap();
    }

    // since we tested `QueryType` with `create`, skip it here
    struct OverrideReq {
        query_id: String,
        field_type: String,
        roles: Vec<String>,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://127.0.0.1:{}{}/{}?field_type={}&query_type=test-multiply",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.query_id,
                self.field_type
            );
            let body = serde_json::to_vec(&self.roles).unwrap();
            hyper::Request::post(uri)
                .body(hyper::Body::from(body))
                .unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            let roles = HelperIdentity::make_three()
                .map(|id| serde_json::to_string(&id).unwrap())
                .to_vec();
            Self {
                query_id: QueryId.as_ref().to_string(),
                field_type: format!("{:?}", FieldType::Fp31),
                roles,
            }
        }
    }

    #[tokio::test]
    async fn malformed_query_id() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_field_type() {
        let req = OverrideReq {
            field_type: "not-a-field-type".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn wrong_num_roles() {
        let req = OverrideReq {
            roles: vec!["1".into(), "2".into()],
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn invalid_role() {
        let req = OverrideReq {
            roles: vec!["1".into(), "2".into(), "not-a-role".into()],
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
