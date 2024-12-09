mod echo;
mod query;
mod metrics;

use axum::Router;

use crate::{
    net::{http_serde, transport::MpcHttpTransport, HttpTransport, Shard},
    sync::Arc,
};

pub fn mpc_router(transport: MpcHttpTransport) -> Router {
    echo::router()
    .merge(metrics::router(transport.clone()))
    .nest(
        http_serde::query::BASE_AXUM_PATH,
        Router::new()
            .merge(query::query_router(transport.clone()))
            .merge(query::h2h_router(transport.inner_transport)),
    )
}

pub fn shard_router(transport: Arc<HttpTransport<Shard>>) -> Router {
    echo::router().nest(
        http_serde::query::BASE_AXUM_PATH,
        Router::new().merge(query::s2s_router(transport)),
    )
}
