use axum::{routing::get, Extension, Router};
use hyper::StatusCode;

use crate::{
    helpers::{routing::RouteId, BodyStream},
    net::{
        http_serde::{self},
        Error, MpcHttpTransport,
    },
};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(transport: Extension<MpcHttpTransport>) -> Result<Vec<u8>, Error> {
    match transport
        .dispatch(RouteId::Metrics, BodyStream::empty())
        .await
    {
        Ok(resp) => Ok(resp.into_body()),
        Err(err) => Err(Error::application(StatusCode::INTERNAL_SERVER_ERROR, err)),
    }
}

pub fn router(transport: MpcHttpTransport) -> Router {
    Router::new()
        .route(http_serde::metrics::AXUM_PATH, get(handler))
        .layer(Extension(transport))
}
