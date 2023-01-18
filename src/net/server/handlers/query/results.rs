use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::get, Extension, Router};
use tokio::sync::{mpsc, oneshot};

/// Handles the completion of the query by blocking the sender until query is completed.
async fn handler(
    req: http_serde::query::results::Request,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
) -> Result<Vec<u8>, Error> {
    let permit = transport_sender.reserve().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();

    // send command, receive response
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Results(req.query_id, tx)),
    };
    permit.send(command);
    let results = rx.await?;

    Ok(results.into_bytes())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::results::AXUM_PATH, get(handler))
        .layer(Extension(transport_sender))
}
