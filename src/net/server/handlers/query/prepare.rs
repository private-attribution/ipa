use crate::{
    helpers::{
        query::{PrepareQuery, QueryCommand},
        transport::TransportCommand,
        CommandEnvelope, CommandOrigin,
    },
    net::{http_serde, server::Error},
    protocol::QueryId,
};
use axum::{
    extract::{Path, RequestParts},
    http::Request,
    routing::post,
    Extension, Json, Router,
};
use hyper::Body;
use tokio::sync::{mpsc, oneshot};

async fn handler(
    query_id: Path<QueryId>,
    query_config: http_serde::query::QueryConfigQueryParams,
    origin_header: http_serde::query::OriginHeader,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let Json(http_serde::query::prepare::RequestBody { roles }) =
        RequestParts::new(req).extract().await?;

    let data = PrepareQuery {
        query_id: *query_id,
        config: query_config.0,
        roles,
    };
    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(origin_header.origin),
        payload: TransportCommand::Query(QueryCommand::Prepare(data, tx)),
    };
    permit.send(command);

    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::prepare::AXUM_PATH, post(handler))
        .layer(Extension(transport_sender))
}
