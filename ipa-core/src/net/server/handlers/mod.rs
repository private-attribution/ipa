mod echo;
mod query;

use axum::Router;

use crate::net::{http_serde, transport::MpcHttpTransport};

pub fn mpc_router(transport: MpcHttpTransport) -> Router {
    echo::router().nest(
        http_serde::query::BASE_AXUM_PATH,
        Router::new()
            .merge(query::query_router(transport.clone()))
            .merge(query::h2h_router(transport)),
    )
}
