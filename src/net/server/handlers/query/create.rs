use crate::{
    helpers::Transport,
    net::{http_serde, Error, HttpTransport},
    query::NewQueryError,
    sync::Arc,
};
use axum::{routing::post, Extension, Json, Router};
use hyper::StatusCode;

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    transport: Extension<Arc<HttpTransport>>,
    req: http_serde::query::create::Request,
) -> Result<Json<http_serde::query::create::ResponseBody>, Error> {
    let transport = Transport::clone_ref(&*transport);
    match transport.receive_query(req.query_config).await {
        Ok(query_id) => Ok(Json(http_serde::query::create::ResponseBody { query_id })),
        Err(err @ NewQueryError::State { .. }) => {
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

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::FieldType,
        helpers::query::{IpaQueryConfig, QueryConfig, QueryType},
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::QueryId,
    };
    use axum::http::Request;
    use futures::{future::poll_immediate, pin_mut};
    use hyper::{Body, StatusCode};
    use tokio::sync::mpsc;

    async fn create_test(expected_query_config: QueryConfig) {
        let (tx, mut rx) = mpsc::channel(1);
        let req = http_serde::query::create::Request::new(expected_query_config);
        let handle = handler(Extension(tx), req);
        pin_mut!(handle);
        // should return pending upon awaiting response
        assert!(matches!(poll_immediate(&mut handle).await, None));

        let res = poll_immediate(rx.recv()).await.unwrap().unwrap();
        assert_eq!(res.origin, CommandOrigin::Other);
        match res.payload {
            TransportCommand::Query(QueryCommand::Create(query_config, responder)) => {
                assert_eq!(query_config, expected_query_config);
                responder.send(QueryId).unwrap();
            }
            other => panic!("expected create command, but got {other:?}"),
        }

        let Json(resp) = poll_immediate(handle).await.unwrap().unwrap();
        assert_eq!(resp.query_id, QueryId);
    }

    #[tokio::test]
    async fn create_test_multiply() {
        create_test(QueryConfig {
            field_type: FieldType::Fp31,
            query_type: QueryType::TestMultiply,
        })
        .await;
    }

    #[tokio::test]
    async fn create_test_ipa() {
        create_test(QueryConfig {
            field_type: FieldType::Fp32BitPrime,
            query_type: QueryType::Ipa(IpaQueryConfig {
                per_user_credit_cap: 1,
                max_breakdown_key: 1,
                attribution_window_seconds: 0,
                num_multi_bits: 3,
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
                "http://127.0.0.1:{}{}?field_type={}&{}",
                port,
                http_serde::query::BASE_AXUM_PATH,
                self.field_type,
                self.query_type_params
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
        attribution_window_seconds: String,
        num_multi_bits: String,
    }

    impl IntoFailingReq for OverrideIPAReq {
        fn into_req(self, port: u16) -> Request<Body> {
            OverrideReq {
                field_type: self.field_type,
                query_type_params: format!(
                    "query_type={}&per_user_credit_cap={}&max_breakdown_key={}&attribution_window_seconds={}&num_multi_bits={}",
                    self.query_type,
                    self.per_user_credit_cap,
                    self.max_breakdown_key,
                    self.attribution_window_seconds,
                    self.num_multi_bits
                ),
            }
            .into_req(port)
        }
    }

    impl Default for OverrideIPAReq {
        fn default() -> Self {
            Self {
                field_type: format!("{:?}", FieldType::Fp32BitPrime),
                query_type: QueryType::IPA_STR.to_string(),
                per_user_credit_cap: "1".into(),
                max_breakdown_key: "1".into(),
                attribution_window_seconds: "0".into(),
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
            attribution_window_seconds: "-1".into(),
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
