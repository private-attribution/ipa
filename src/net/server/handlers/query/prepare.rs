use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::post, Extension, Router};
use tokio::sync::{mpsc, oneshot};

async fn handler(
    req: http_serde::query::prepare::Request,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;
    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(req.origin),
        payload: TransportCommand::Query(QueryCommand::Prepare(req.data, tx)),
    };
    permit.send(command);

    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::prepare::AXUM_PATH, post(handler))
        .layer(Extension(transport_sender))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        ff::FieldType,
        helpers::{
            query::{PrepareQuery, QueryConfig, QueryType},
            HelperIdentity, RoleAssignment,
        },
        net::server::handlers::query::test_helpers::{assert_req_fails_with, IntoFailingReq},
        protocol::QueryId,
    };
    use axum::http::Request;
    use futures::pin_mut;
    use futures_util::future::poll_immediate;
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

        let (tx, mut rx) = mpsc::channel(1);
        let handle = handler(req.clone(), Extension(tx));
        pin_mut!(handle);

        // should be pending while waiting for `rx`
        assert!(matches!(poll_immediate(&mut handle).await, None));
        let res = poll_immediate(rx.recv()).await.unwrap().unwrap();
        assert_eq!(res.origin, CommandOrigin::Helper(req.origin));
        match res.payload {
            TransportCommand::Query(QueryCommand::Prepare(prepare_query, responder)) => {
                assert_eq!(prepare_query, req.data);
                responder.send(()).unwrap();
            }
            other => panic!("expected create command, but got {other:?}"),
        }

        poll_immediate(handle).await.unwrap().unwrap();
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
