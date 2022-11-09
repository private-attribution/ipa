use crate::net::server::MpcHelperServerError;
use axum::{
    extract::{FromRequest, Query, RequestParts},
    Json,
};
use hyper::{Body, Request};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct Payload {
    pub query_args: HashMap<String, String>,
    pub headers: HashMap<String, String>,
}

#[allow(dead_code)]
pub async fn handler(req: Request<Body>) -> Result<Json<Payload>, MpcHelperServerError> {
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

#[cfg(test)]
mod tests {
    use crate::net::server::handlers::echo::handler;
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
