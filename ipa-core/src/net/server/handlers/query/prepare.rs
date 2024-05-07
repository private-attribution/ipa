use axum::{response::IntoResponse, routing::post, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{BodyStream, Transport},
    net::{http_serde, server::ClientIdentity, Error, HttpTransport},
    query::PrepareQueryError,
    sync::Arc,
};

/// Called by whichever peer helper is the leader for an individual query, to initiatialize
/// processing of that query.
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    _: Extension<ClientIdentity>, // require that client is an authenticated helper
    req: http_serde::query::prepare::Request,
) -> Result<(), Error> {
    let transport = Transport::clone_ref(&*transport);
    let _ = transport
        .dispatch(req.data, BodyStream::empty())
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
    use axum::{http::Request, Extension};
    use hyper::{Body, StatusCode};

    use crate::{
        ff::FieldType,
        helpers::{
            make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType::TestMultiply},
            routing::{Addr, RouteId},
            BodyStream, HelperIdentity, HelperResponse, RoleAssignment,
        },
        net::{
            http_serde,
            server::{
                handlers::query::{
                    prepare::handler,
                    test_helpers::{assert_req_fails_with, IntoFailingReq, MaybeExtensionExt},
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
        let test_server = TestServer::builder()
            .with_request_handler(make_owned_handler(
                move |addr: Addr<HelperIdentity>, _: BodyStream| {
                    let expected_prepare_query = expected_prepare_query.clone();
                    async move {
                        let RouteId::PrepareQuery = addr.route else {
                            panic!("unexpected call");
                        };

                        let actual_prepare_query = addr.into::<PrepareQuery>().unwrap();
                        assert_eq!(actual_prepare_query, expected_prepare_query);
                        Ok(HelperResponse::ok())
                    }
                },
            ))
            .build()
            .await;

        handler(
            Extension(test_server.transport),
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
