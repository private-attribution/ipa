use axum::{
    extract::{Path, Query},
    routing::get,
    Extension, Router,
};
use hyper::StatusCode;

use crate::{
    helpers::{query::CompareStatusRequest, ApiError, BodyStream},
    net::{
        http_serde::query::status_match::{
            StatusQueryString, {self},
        },
        server::Error,
        HttpTransport, Shard,
    },
    protocol::QueryId,
    query::QueryStatusError,
    sync::Arc,
};

async fn handler(
    transport: Extension<Arc<HttpTransport<Shard>>>,
    Path(query_id): Path<QueryId>,
    Query(StatusQueryString { status }): Query<StatusQueryString>,
) -> Result<(), Error> {
    let req = CompareStatusRequest { query_id, status };
    match Arc::clone(&transport)
        .dispatch(req, BodyStream::empty())
        .await
    {
        Ok(_) => Ok(()),
        Err(ApiError::QueryStatus(QueryStatusError::DifferentStatus { my_status, .. })) => {
            Err(crate::net::error::ShardQueryStatusMismatchError { actual: my_status }.into())
        }
        Err(e) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, e)),
    }
}

pub fn router(transport: Arc<HttpTransport<Shard>>) -> Router {
    Router::new()
        .route(status_match::AXUM_PATH, get(handler))
        .layer(Extension(transport))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::{borrow::Borrow, sync::Arc};

    use axum::{
        body::Body,
        http::uri::{Authority, Scheme},
    };
    use hyper::StatusCode;

    use crate::{
        helpers::{
            make_owned_handler,
            query::CompareStatusRequest,
            routing::{Addr, RouteId},
            ApiError, BodyStream, HelperResponse, RequestHandler,
        },
        net::{
            error::ShardQueryStatusMismatchError,
            http_serde::query::status_match::try_into_http_request,
            server::ClientIdentity,
            test::{TestServer, TestServerBuilder},
            Error, Shard,
        },
        protocol::QueryId,
        query::{QueryStatus, QueryStatusError},
        sharding::ShardIndex,
    };

    fn for_status(status: QueryStatus) -> CompareStatusRequest {
        CompareStatusRequest {
            query_id: QueryId,
            status,
        }
    }

    fn http_request<B: Borrow<CompareStatusRequest>>(req: B) -> hyper::Request<axum::body::Body> {
        try_into_http_request(
            req.borrow(),
            Scheme::HTTP,
            Authority::from_static("localhost"),
        )
        .unwrap()
    }

    fn authenticated(mut req: hyper::Request<Body>) -> hyper::Request<Body> {
        req.extensions_mut()
            .insert(ClientIdentity(ShardIndex::from(2)));
        req
    }

    fn handler_status_match(expected_status: QueryStatus) -> Arc<dyn RequestHandler<ShardIndex>> {
        make_owned_handler(
            move |addr: Addr<ShardIndex>, _data: BodyStream| async move {
                let RouteId::QueryStatus = addr.route else {
                    panic!("unexpected call");
                };
                let req = addr.into::<CompareStatusRequest>().unwrap();
                assert_eq!(req.query_id, QueryId);
                assert_eq!(req.status, expected_status);
                Ok(HelperResponse::ok())
            },
        )
    }

    fn handler_status_mismatch(
        expected_status: QueryStatus,
    ) -> Arc<dyn RequestHandler<ShardIndex>> {
        assert_ne!(expected_status, QueryStatus::Running);

        make_owned_handler(
            move |addr: Addr<ShardIndex>, _data: BodyStream| async move {
                let RouteId::QueryStatus = addr.route else {
                    panic!("unexpected call");
                };
                let req = addr.into::<CompareStatusRequest>().unwrap();
                assert_eq!(req.query_id, QueryId);
                Err(ApiError::QueryStatus(QueryStatusError::DifferentStatus {
                    query_id: QueryId,
                    my_status: QueryStatus::Running,
                    other_status: expected_status,
                }))
            },
        )
    }

    #[tokio::test]
    async fn status_success() {
        let expected_status = QueryStatus::Running;
        let req = authenticated(http_request(for_status(expected_status)));

        TestServer::<Shard>::oneshot_success(req, handler_status_match(expected_status)).await;
    }

    #[tokio::test]
    async fn status_client_success() {
        let expected_status = QueryStatus::Running;
        let test_server = TestServerBuilder::<Shard>::default()
            .with_request_handler(handler_status_match(expected_status))
            .build()
            .await;

        test_server
            .client
            .status_match(for_status(expected_status))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn status_client_mismatch() {
        let diff_status = QueryStatus::Preparing;
        let test_server = TestServerBuilder::<Shard>::default()
            .with_request_handler(handler_status_mismatch(diff_status))
            .build()
            .await;
        let e = test_server
            .client
            .status_match(for_status(diff_status))
            .await
            .unwrap_err();
        assert!(matches!(
            e,
            Error::ShardQueryStatusMismatch {
                error: ShardQueryStatusMismatchError {
                    actual: QueryStatus::Running
                },
            }
        ));
    }

    #[tokio::test]
    async fn status_mismatch() {
        let req_status = QueryStatus::Completed;
        let handler = handler_status_mismatch(req_status);
        let req = authenticated(http_request(for_status(req_status)));

        let resp = TestServer::<Shard>::oneshot(req, handler).await;
        assert_eq!(StatusCode::PRECONDITION_FAILED, resp.status());
    }

    #[tokio::test]
    async fn other_query_error() {
        let handler = make_owned_handler(
            move |_addr: Addr<ShardIndex>, _data: BodyStream| async move {
                Err(ApiError::QueryStatus(QueryStatusError::NoSuchQuery(
                    QueryId,
                )))
            },
        );
        let req = authenticated(http_request(for_status(QueryStatus::Running)));

        let resp = TestServer::<Shard>::oneshot(req, handler).await;
        assert_eq!(StatusCode::INTERNAL_SERVER_ERROR, resp.status());
    }

    #[tokio::test]
    async fn unauthenticated() {
        assert_eq!(
            StatusCode::UNAUTHORIZED,
            TestServer::<Shard>::oneshot(
                http_request(for_status(QueryStatus::Running)),
                make_owned_handler(|_, _| async move { unimplemented!() }),
            )
            .await
            .status()
        );
    }

    #[tokio::test]
    async fn server_error() {
        assert_eq!(
            StatusCode::INTERNAL_SERVER_ERROR,
            TestServer::<Shard>::oneshot(
                authenticated(http_request(for_status(QueryStatus::Running))),
                make_owned_handler(|_, _| async move { Err(ApiError::BadRequest("".into())) }),
            )
            .await
            .status()
        );
    }
}
