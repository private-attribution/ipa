use axum::{routing::post, Extension, Json, Router};
use hyper::StatusCode;

use crate::{
    helpers::{ApiError, BodyStream, Transport},
    net::{http_serde, Error, HttpTransport},
    query::NewQueryError,
    sync::Arc,
};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::create::Request,
) -> Result<Json<http_serde::query::create::ResponseBody>, Error> {
    let transport = Transport::clone_ref(&*transport);
    match transport
        .dispatch(req.query_config, BodyStream::empty())
        .await
    {
        Ok(resp) => Ok(Json(resp.try_into()?)),
        Err(err @ ApiError::NewQuery(NewQueryError::State { .. })) => {
            Err(Error::application(StatusCode::CONFLICT, err))
        }
        Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

pub fn router(transport: Arc<HttpTransport>) -> Router {
    Router::new()
        .route(http_serde::query::create::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::num::NonZeroU32;

    use axum::http::Request;
    use hyper::{
        http::uri::{Authority, Scheme},
        Body, StatusCode,
    };

    use crate::{
        ff::FieldType,
        helpers::{
            make_owned_handler,
            query::{IpaQueryConfig, PrepareQuery, QueryConfig, QueryType},
            routing::{Addr, RouteId},
            HelperIdentity, HelperResponse, Role, RoleAssignment,
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
            test::TestServer,
        },
        protocol::QueryId,
    };

    async fn create_test(expected_query_config: QueryConfig) {
        let test_server = TestServer::builder()
            .with_request_handler(make_owned_handler(
                move |addr: Addr<HelperIdentity>, _| async move {
                    let RouteId::ReceiveQuery = addr.route else {
                        panic!("unexpected call");
                    };

                    let query_config = addr.into().unwrap();
                    assert_eq!(query_config, expected_query_config);
                    Ok(HelperResponse::from(PrepareQuery {
                        query_id: QueryId,
                        config: query_config,
                        roles: RoleAssignment::try_from([Role::H1, Role::H2, Role::H3]).unwrap(),
                    }))
                },
            ))
            .build()
            .await;
        let req = http_serde::query::create::Request::new(expected_query_config);
        let req = req
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        let resp = test_server.server.handle_req(req).await;

        let status = resp.status();
        let body_bytes = hyper::body::to_bytes(resp.into_body()).await.unwrap();
        let response_str = String::from_utf8(body_bytes.to_vec()).unwrap();

        assert_eq!(StatusCode::OK, status, "Request failed: {}", &response_str);

        let http_serde::query::create::ResponseBody { query_id } =
            serde_json::from_slice(&body_bytes).unwrap();
        assert_eq!(QueryId, query_id);
    }

    #[tokio::test]
    async fn create_test_multiply() {
        create_test(QueryConfig::new(QueryType::TestMultiply, FieldType::Fp31, 1).unwrap()).await;
    }

    #[tokio::test]
    async fn create_test_ipa_no_attr_window() {
        create_test(
            QueryConfig::new(
                QueryType::OprfIpa(IpaQueryConfig {
                    per_user_credit_cap: 1,
                    max_breakdown_key: 1,
                    attribution_window_seconds: None,
                    num_multi_bits: 3,
                    plaintext_match_keys: true,
                }),
                FieldType::Fp32BitPrime,
                1,
            )
            .unwrap(),
        )
        .await;
    }

    #[tokio::test]
    async fn create_test_ipa_with_attr_window() {
        create_test(QueryConfig {
            size: 1.try_into().unwrap(),
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::OprfIpa(IpaQueryConfig {
                per_user_credit_cap: 1,
                max_breakdown_key: 1,
                attribution_window_seconds: NonZeroU32::new(86_400),
                num_multi_bits: 3,
                plaintext_match_keys: true,
            }),
        })
        .await;
    }

    struct OverrideReq {
        field_type: String,
        query_type_params: String,
    }

    impl IntoFailingReq for OverrideReq {
        fn into_req(self, port: u16) -> hyper::Request<hyper::Body> {
            let uri = format!(
                "http://localhost:{p}{path}?size=1&field_type={f}&{qt}",
                p = port,
                path = http_serde::query::BASE_AXUM_PATH,
                f = self.field_type,
                qt = self.query_type_params
            );
            hyper::Request::post(uri)
                .body(hyper::Body::empty())
                .unwrap()
        }
    }

    struct OverrideMulReq {
        field_type: String,
        query_type: String,
    }

    impl IntoFailingReq for OverrideMulReq {
        fn into_req(self, port: u16) -> Request<Body> {
            OverrideReq {
                field_type: self.field_type,
                query_type_params: format!("query_type={}", self.query_type),
            }
            .into_req(port)
        }
    }

    impl Default for OverrideMulReq {
        fn default() -> Self {
            Self {
                field_type: format!("{:?}", FieldType::Fp31),
                query_type: QueryType::TEST_MULTIPLY_STR.to_string(),
            }
        }
    }

    #[tokio::test]
    async fn malformed_field_type() {
        let req = OverrideMulReq {
            field_type: "not-a-field-type".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_query_type_mul() {
        let req = OverrideMulReq {
            query_type: "malformed_mul".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    struct OverrideIPAReq {
        field_type: String,
        query_type: String,
        per_user_credit_cap: String,
        max_breakdown_key: String,
        attribution_window_seconds: Option<String>,
        num_multi_bits: String,
    }

    impl IntoFailingReq for OverrideIPAReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let mut query = format!(
                "query_type={}&per_user_credit_cap={}&max_breakdown_key={}&num_multi_bits={}",
                self.query_type,
                self.per_user_credit_cap,
                self.max_breakdown_key,
                self.num_multi_bits
            );
            if let Some(window) = self.attribution_window_seconds {
                query.push_str(&format!("&attribution_window_seconds={window}"));
            }
            OverrideReq {
                field_type: self.field_type,
                query_type_params: query,
            }
            .into_req(port)
        }
    }

    impl Default for OverrideIPAReq {
        fn default() -> Self {
            Self {
                field_type: format!("{:?}", FieldType::Fp32BitPrime),
                query_type: QueryType::OPRF_IPA_STR.to_string(),
                per_user_credit_cap: "1".into(),
                max_breakdown_key: "1".into(),
                attribution_window_seconds: None,
                num_multi_bits: "3".into(),
            }
        }
    }

    #[tokio::test]
    async fn malformed_field_type_ipa() {
        let req = OverrideIPAReq {
            field_type: "invalid_field".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_query_type_ipa() {
        let req = OverrideIPAReq {
            query_type: "not_ipa".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_per_user_credit_cap_ipa() {
        let req = OverrideIPAReq {
            per_user_credit_cap: "-1".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_max_breakdown_key_ipa() {
        let req = OverrideIPAReq {
            max_breakdown_key: "-1".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_attribution_window_seconds_ipa() {
        let req = OverrideIPAReq {
            attribution_window_seconds: Some("-1".to_string()),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_num_multi_bits_ipa() {
        let req = OverrideIPAReq {
            num_multi_bits: "-1".into(),
            ..Default::default()
        };
        assert_req_fails_with(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
