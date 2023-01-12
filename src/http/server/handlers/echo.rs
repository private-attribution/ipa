use crate::http::server::Error;
use axum::{
    extract::{FromRequest, Query, RequestParts},
    routing::get,
    Json, Router,
};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    pub query_args: HashMap<String, String>,
    pub headers: HashMap<String, String>,
}

async fn handler(req: Request<Body>) -> Result<Json<Payload>, Error> {
    let mut parts = RequestParts::new(req);

    let query: Query<HashMap<String, String>> = Query::from_request(&mut parts).await?;
    let headers = parts
        .headers()
        .iter()
        .filter_map(|(name, value)| match value.to_str() {
            Ok(header_value) => Some((name.to_string(), header_value.to_string())),
            Err(_) => None,
        })
        .collect();

    Ok(Json(Payload {
        query_args: query.0,
        headers,
    }))
}

pub fn router() -> Router {
    Router::new().route("/echo", get(handler))
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use hyper::{Body, Request};

    #[tokio::test]
    async fn happy_case() {
        let request = Request::builder()
            .uri("/?foo=bar")
            .header("echo", "v")
            .body(Body::empty())
            .unwrap();

        let response = handler(request).await.expect("Failed to handle request");
        assert_eq!("bar", response.query_args["foo"]);
        assert_eq!("v", response.headers["echo"]);
    }
}
