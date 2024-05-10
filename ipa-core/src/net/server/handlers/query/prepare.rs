use axum::{extract::Path, response::IntoResponse, routing::post, Extension, Json, Router};
use hyper::StatusCode;

use crate::{
    helpers::{query::PrepareQuery, BodyStream, Transport},
    net::{
        http_serde::{
            self,
            query::{prepare::RequestBody, QueryConfigQueryParams},
        },
        server::ClientIdentity,
        Error, HttpTransport,
    },
    protocol::QueryId,
    query::PrepareQueryError,
    sync::Arc,
};

/// Called by whichever peer helper is the leader for an individual query, to initiatialize
/// processing of that query.
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    _: Extension<ClientIdentity>, // require that client is an authenticated helper
    Path(query_id): Path<QueryId>,
    QueryConfigQueryParams(config): QueryConfigQueryParams,
    Json(RequestBody { roles }): Json<RequestBody>,
) -> Result<(), Error> {
    let data = PrepareQuery {
        query_id,
        config,
        roles,
    };
    let transport = Transport::clone_ref(&*transport);
    let _ = transport
        .dispatch(data, BodyStream::empty())
        .await
        .map_err(|e| Error::application(StatusCode::INTERNAL_SERVER_ERROR, e))?;

    Ok(())
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
    use hyper::{header::CONTENT_TYPE, Body, StatusCode};
    use serde::Serialize;

    use crate::{
        ff::FieldType,
        helpers::{
            make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            routing::RouteId,
            HelperIdentity, HelperResponse, RoleAssignment,
        },
        net::{
            http_serde,
            server::{
                handlers::query::test_helpers::{
                    assert_fails_with, assert_success_with, MaybeExtensionExt,
                },
                ClientIdentity,
            },
            APPLICATION_JSON,
        },
        protocol::QueryId,
    };

    #[tokio::test]
    async fn prepare_test() {
        let req = OverrideReq::default();
        let handler = make_owned_handler(move |addr, _| async move {
            let RouteId::PrepareQuery = addr.route else {
                panic!("unexpected call");
            };
            let expected_prepare_query = PrepareQuery {
                query_id: QueryId,
                config: QueryConfig::new(TestMultiply, FieldType::Fp31, 1).unwrap(),
                roles: RoleAssignment::new(HelperIdentity::make_three()),
            };
            let actual_prepare_query = addr.into::<PrepareQuery>().unwrap();
            assert_eq!(actual_prepare_query, expected_prepare_query);
            Ok(HelperResponse::ok())
        });
        assert_success_with(req.into(), handler).await;
    }

    // since we tested `QueryType` with `create`, skip it here
    // More lenient version of Request, specifically so to test failure scenarios
    struct OverrideReq {
        client_id: Option<ClientIdentity>,
        query_id: String,
        field_type: String,
        size: Option<i32>,
        roles: OverrideReqRoles,
    }

    #[derive(Serialize)]
    struct OverrideReqBody {
        roles: OverrideReqRoles,
    }

    #[derive(Serialize)]
    struct OverrideReqRoles {
        helper_roles: Vec<i8>,
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                client_id: Some(ClientIdentity(HelperIdentity::TWO)),
                query_id: QueryId.as_ref().to_string(),
                field_type: format!("{:?}", FieldType::Fp31),
                size: Some(1),
                roles: OverrideReqRoles {
                    helper_roles: vec![1, 2, 3],
                },
            }
        }
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{path}/{query_id}?{size}field_type={ft}&query_type=test-multiply",
                size = val.size.map_or(String::new(), |v| format!("size={v}&")),
                path = http_serde::query::BASE_AXUM_PATH,
                query_id = val.query_id,
                ft = val.field_type
            );
            let body = OverrideReqBody { roles: val.roles };
            let body = serde_json::to_string(&body).unwrap();
            hyper::Request::post(uri)
                .header(CONTENT_TYPE, APPLICATION_JSON)
                .maybe_extension(val.client_id)
                .body(hyper::Body::from(body))
                .unwrap()
        }
    }

    #[tokio::test]
    async fn malformed_query_id() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn malformed_field_type() {
        let req = OverrideReq {
            field_type: "not-a-field-type".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn wrong_num_roles() {
        let req = OverrideReq {
            roles: OverrideReqRoles {
                helper_roles: vec![1, 2],
            },
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn invalid_role() {
        let req = OverrideReq {
            roles: OverrideReqRoles {
                helper_roles: vec![-1, 2, 3],
            },
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn auth_required() {
        let req = OverrideReq {
            client_id: None,
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNAUTHORIZED).await;
    }

    #[tokio::test]
    async fn query_size_unspecified() {
        let req = OverrideReq {
            size: None,
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn query_size_zero() {
        let req = OverrideReq {
            size: Some(0),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn query_size_negative() {
        let req = OverrideReq {
            size: Some(-1),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
