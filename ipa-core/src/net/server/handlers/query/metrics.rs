use axum::{routing::get, Router};

use crate::net::http_serde::{self};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    // transport: Extension<MpcHttpTransport>,
    // QueryConfigQueryParams(query_config): QueryConfigQueryParams,
) -> &'static str {
    // match transport.dispatch(query_config, BodyStream::empty()).await {
    //     Ok(resp) => Ok(Json(resp.try_into()?)),
    //     Err(err @ ApiError::NewQuery(NewQueryError::State { .. })) => {
    //         Err(Error::application(StatusCode::CONFLICT, err))
    //     }
    //     Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    // }
    "hello world"
}

pub fn router() -> Router {
    Router::new().route(http_serde::metrics::AXUM_PATH, get(handler))
}