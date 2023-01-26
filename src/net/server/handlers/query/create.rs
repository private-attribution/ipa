use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::post, Extension, Json, Router};
use tokio::sync::{mpsc, oneshot};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: http_serde::query::create::Request,
) -> Result<Json<http_serde::query::create::ResponseBody>, Error> {
    let permit = transport_sender.reserve().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();

    // send command, receive response
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Create(req.query_config, tx)),
    };
    permit.send(command);
    let query_id = rx.await?;

    Ok(Json(http_serde::query::create::ResponseBody { query_id }))
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::create::AXUM_PATH, post(handler))
        .layer(Extension(transport_sender))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ff::FieldType;
    use crate::helpers::query::{IPAQueryConfig, QueryConfig, QueryType};
    use crate::net::server::handlers::query::test_helpers::{poll_immediate, resp_eq, IntoReq};
    use crate::protocol::QueryId;
    use hyper::StatusCode;

    async fn create_test(expected_query_config: QueryConfig) {
        let (tx, mut rx) = mpsc::channel(1);
        let req = http_serde::query::create::Request::new(expected_query_config.clone());
        let mut handle = Box::pin(handler(Extension(tx), req));
        // should return pending upon awaiting response
        assert!(poll_immediate(&mut handle).is_pending());

        let res = rx.recv().await.unwrap();
        assert_eq!(res.origin, CommandOrigin::Other);
        match res.payload {
            TransportCommand::Query(QueryCommand::Create(query_config, responder)) => {
                assert_eq!(query_config, expected_query_config);
                responder.send(QueryId).unwrap();
            }
            other => panic!("expected create command, but got {other:?}"),
        }

        let Json(resp) = handle.await.unwrap();
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
            query_type: QueryType::IPA(IPAQueryConfig {
                num_bits: 20,
                per_user_credit_cap: 1,
                max_breakdown_key: 1,
            }),
        })
        .await;
    }

    struct OverrideReq {
        field_type: String,
        query_type_params: String,
    }

    impl IntoReq for OverrideReq {
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

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                field_type: FieldType::Fp31.as_ref().to_string(),
                query_type_params: format!("query_type={}", QueryType::TEST_MULTIPLY_STR),
            }
        }
    }

    #[tokio::test]
    async fn malformed_field_type() {
        let req = OverrideReq {
            field_type: "not-a-field-type".into(),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_query_type_mul() {
        let req = OverrideReq {
            query_type_params: "query_type=malformed_mul".into(),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    // fn ipa_query_type_params(
    //     query_type: String,
    //     num_bits: String,
    //     per_user_credit_cap: String,
    //     max_breakdown_key: String,
    // ) -> String {
    //     format!("query_type={query_type}&num_bits={num_bits}&per_user_credit_cap={per_user_credit_cap}&max_breakdown_key={max_breakdown_key}")
    // }

    #[tokio::test]
    async fn malformed_query_type_ipa() {
        let req = OverrideReq {
            query_type_params: format!("query_type={}", QueryType::IPA_STR),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }
}
