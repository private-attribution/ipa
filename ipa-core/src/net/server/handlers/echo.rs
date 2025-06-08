use std::collections::HashMap;

use axum::{Json, Router, extract::Query, routing::get};
use hyper::HeaderMap;

use crate::net::{
    http_serde::{self, echo::Request},
    server::Error,
};

#[allow(clippy::unused_async)] // needs to be async for axum handler
async fn handler(
    Query(query_params): Query<HashMap<String, String>>,
    hyper_headers: HeaderMap,
) -> Result<Json<http_serde::echo::Request>, Error> {
    let headers = hyper_headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|header_value| (name.to_string(), header_value.to_string()))
        })
        .collect();
    Ok(Json(Request {
        query_params,
        headers,
    }))
}

pub fn router() -> Router {
    Router::new().route(http_serde::echo::AXUM_PATH, get(handler))
}

#[cfg(all(test, unit_test))]
mod tests {
    use axum::body::Body;
    use bytes::Buf;
    use http_body_util::BodyExt;
    use hyper::{Request, StatusCode};
    use serde_json::{Value, json};
    use tower::ServiceExt;

    use super::*;

    #[tokio::test]
    async fn happy_case() {
        // No transport in this handler, hence no need for a `TestServer`.
        let response = router()
            .oneshot(
                Request::builder()
                    .uri("/echo?echo=v")
                    .header("foo", "bar")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().aggregate();
        let body: Value = serde_json::from_reader(body.reader()).unwrap();
        assert_eq!(
            body,
            json!({"query_params": {"echo": "v"}, "headers": {"foo": "bar"}})
        );
    }
}
