use axum::{Extension, Json, Router, routing::post};
use hyper::StatusCode;

use crate::{
    helpers::{ApiError, BodyStream},
    net::{
        Error,
        http_serde::{self, query::QueryConfigQueryParams},
        transport::MpcHttpTransport,
    },
    query::NewQueryError,
};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    transport: Extension<MpcHttpTransport>,
    QueryConfigQueryParams(query_config): QueryConfigQueryParams,
) -> Result<Json<http_serde::query::create::ResponseBody>, Error> {
    match transport.dispatch(query_config, BodyStream::empty()).await {
        Ok(resp) => Ok(Json(resp.try_into()?)),
        Err(err @ ApiError::NewQuery(NewQueryError::State { .. })) => {
            Err(Error::application(StatusCode::CONFLICT, err))
        }
        Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

pub fn router(transport: MpcHttpTransport) -> Router {
    Router::new()
        .route(http_serde::query::create::AXUM_PATH, post(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {

    use axum::body::Body;
    use hyper::{
        StatusCode,
        http::uri::{Authority, Scheme},
    };

    use crate::{
        ff::FieldType,
        helpers::{
            HelperResponse, Role, RoleAssignment, make_owned_handler,
            query::{PrepareQuery, QueryConfig, QueryType},
            routing::RouteId,
        },
        net::{
            http_serde,
            server::handlers::query::test_helpers::{assert_fails_with, assert_success_with},
        },
        protocol::QueryId,
    };

    async fn create_test(expected_query_config: QueryConfig) {
        let req = http_serde::query::create::Request::new(expected_query_config)
            .try_into_http_request(Scheme::HTTP, Authority::from_static("localhost"))
            .unwrap();
        let handler = make_owned_handler(move |addr, _| async move {
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
        });
        let resp = assert_success_with(req, handler).await;
        let http_serde::query::create::ResponseBody { query_id } =
            serde_json::from_slice(&resp).unwrap();
        assert_eq!(QueryId, query_id);
    }

    #[tokio::test]
    async fn create_test_multiply() {
        create_test(QueryConfig::new(QueryType::TestMultiply, FieldType::Fp31, 1).unwrap()).await;
    }

    struct OverrideReq {
        field_type: String,
        query_type_params: String,
    }

    impl From<OverrideReq> for hyper::Request<Body> {
        fn from(val: OverrideReq) -> Self {
            let uri = format!(
                "http://localhost{path}?size=1&field_type={f}&{qt}",
                path = http_serde::query::BASE_AXUM_PATH,
                f = val.field_type,
                qt = val.query_type_params
            );
            hyper::Request::post(uri).body(Body::empty()).unwrap()
        }
    }

    struct OverrideMulReq {
        field_type: String,
        query_type: String,
    }

    impl From<OverrideMulReq> for hyper::Request<Body> {
        fn from(val: OverrideMulReq) -> Self {
            OverrideReq {
                field_type: val.field_type,
                query_type_params: format!("query_type={}", val.query_type),
            }
            .into()
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
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_query_type_mul() {
        let req = OverrideMulReq {
            query_type: "malformed_mul".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    struct OverrideIPAReq {
        field_type: String,
        query_type: String,
        per_user_credit_cap: String,
        max_breakdown_key: String,
        attribution_window_seconds: Option<String>,
        with_dp: String,
        epsilon: String,
    }

    impl From<OverrideIPAReq> for hyper::Request<Body> {
        fn from(val: OverrideIPAReq) -> Self {
            let mut query = format!(
                "query_type={}&per_user_credit_cap={}&max_breakdown_key={}&with_dp={}&epsilon={}",
                val.query_type,
                val.per_user_credit_cap,
                val.max_breakdown_key,
                val.with_dp,
                val.epsilon,
            );

            #[allow(clippy::format_push_string)]
            if let Some(window) = val.attribution_window_seconds {
                query.push_str(&format!("&attribution_window_seconds={window}"));
            }
            OverrideReq {
                field_type: val.field_type,
                query_type_params: query,
            }
            .into()
        }
    }

    impl Default for OverrideIPAReq {
        fn default() -> Self {
            Self {
                field_type: format!("{:?}", FieldType::Fp32BitPrime),
                query_type: QueryType::TEST_MULTIPLY_STR.to_string(),
                per_user_credit_cap: "1".into(),
                max_breakdown_key: "1".into(),
                attribution_window_seconds: None,
                with_dp: "1".into(),
                epsilon: "3.0".into(),
            }
        }
    }

    #[tokio::test]
    async fn malformed_field_type_ipa() {
        let req = OverrideIPAReq {
            field_type: "invalid_field".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_query_type_ipa() {
        let req = OverrideIPAReq {
            query_type: "not_ipa".into(),
            ..Default::default()
        };
        assert_fails_with(req.into(), StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
