use std::sync::Arc;

use axum::{response::IntoResponse, routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    net::{http_serde, server::ClientIdentity, HttpTransport},
    query::PrepareQueryError,
};

/// Called by whichever peer helper is the leader for an individual query, to initiatialize
/// processing of that query.
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    _from: Extension<ClientIdentity>, // require that client is an authenticated helper
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

#[cfg(all(test, unit_test))]
mod tests {
    use std::future::ready;

    use axum::http::Request;
    use hyper::{Body, StatusCode};

    use super::*;
    use crate::{
        ff::FieldType,
        helpers::{
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            HelperIdentity, RoleAssignment, TransportCallbacks,
        },
        net::{
            server::{
                handlers::query::{
                    test_helpers::{assert_req_fails_with, IntoFailingReq},
                    MaybeExtensionExt,
                },
                ClientIdentity,
            },
            test::TestServer,
        },
        protocol::QueryId,
    };

    #[tokio::test]
    async fn prepare_test() {
        let req = http_serde::query::prepare::Request::new(PrepareQuery {
            query_id: QueryId,
            config: QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap(),
            roles: RoleAssignment::new(HelperIdentity::make_three()),
        });
        let expected_prepare_query = req.data.clone();

        let cb = TransportCallbacks {
            prepare_query: Box::new(move |_transport, prepare_query| {
                assert_eq!(prepare_query, expected_prepare_query);
                Box::pin(ready(Ok(())))
            }),
            ..Default::default()
        };
        let TestServer { transport, .. } = TestServer::builder().with_callbacks(cb).build().await;
        handler(
            Extension(transport),
            Extension(ClientIdentity(HelperIdentity::TWO)),
            req.clone(),
        )
        .await
        .unwrap();
    }

    // since we tested `QueryType` with `create`, skip it here
    struct OverrideReq {
        client_id: Option<ClientIdentity>,
        query_id: String,
        field_type: String,
        size: Option<i32>,
        roles: Vec<String>,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://localhost:{port}{path}/{query_id}?{size}field_type={ft}&query_type=test-multiply",
                size = self.size.map_or(String::new(), |v| format!("size={v}&")),
                path = http_serde::query::BASE_AXUM_PATH,
                query_id = self.query_id,
                ft = self.field_type
            );
            let body = serde_json::to_vec(&self.roles).unwrap();
            hyper::Request::post(uri)
                .maybe_extension(self.client_id)
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
                client_id: Some(ClientIdentity(HelperIdentity::TWO)),
                query_id: QueryId.as_ref().to_string(),
                field_type: format!("{:?}", FieldType::Fp31),
                size: Some(1),
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
        assert_req_fails_with(req, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn invalid_role() {
        let req = OverrideReq {
            roles: vec!["1".into(), "2".into(), "not-a-role".into()],
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn auth_required() {
        let req = OverrideReq {
            client_id: None,
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn query_size_unspecified() {
        let req = OverrideReq {
            size: None,
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn query_size_invalid() {
        assert_req_fails_with(
            OverrideReq {
                size: Some(0),
                ..Default::default()
            },
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
        assert_req_fails_with(
            OverrideReq {
                size: Some(-1),
                ..Default::default()
            },
            StatusCode::UNPROCESSABLE_ENTITY,
        )
        .await;
    }
}
