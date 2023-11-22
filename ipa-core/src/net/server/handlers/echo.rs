use axum::{routing::get, Json, Router};

use crate::net::{http_serde, server::Error};

#[allow(clippy::unused_async)] // needs to be async for axum handler
async fn handler(req: http_serde::echo::Request) -> Result<Json<http_serde::echo::Request>, Error> {
    Ok(Json(req))
}

pub fn router() -> Router {
    Router::new().route(http_serde::echo::AXUM_PATH, get(handler))
}

#[cfg(all(test, unit_test))]
mod tests {
    use std::collections::HashMap;

    use super::*;

    #[tokio::test]
    async fn happy_case() {
        let req = http_serde::echo::Request::new(
            HashMap::from([(String::from("foo"), String::from("bar"))]),
            HashMap::from([(String::from("echo"), String::from("v"))]),
        );
        let Json(resp) = handler(req.clone())
            .await
            .expect("Failed to handle request");
        assert_eq!(req, resp);
    }
}
