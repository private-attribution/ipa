use crate::cli::net::server::MpcServerError;
use axum::http::Request;
use hyper::Body;

#[allow(clippy::unused_async)] // TODO: this is a stub for now
pub async fn handler(_req: Request<Body>) -> Result<(), MpcServerError> {
    Ok(())
}
