use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
    protocol::QueryId,
};
use axum::extract::Path;
use axum::routing::get;
use axum::{Extension, Router};
use hyper::{Body, Request};
use tokio::sync::{mpsc, oneshot};

/// Handles the completion of the query by blocking the sender until query is completed.
async fn handler(
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    query_id: Path<QueryId>,
    _req: Request<Body>,
) -> Result<Vec<u8>, Error> {
    let permit = transport_sender.reserve().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();

    // send command, receive response
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Results(query_id.0, tx)),
    };
    permit.send(command);
    let results = rx.await?;

    Ok(results.into_bytes())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::QUERY_RESULTS_AXUM_PATH, get(handler))
        .layer(Extension(transport_sender))
}
