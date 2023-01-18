use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::post, Extension, Router};
use tokio::sync::{mpsc, oneshot};

async fn handler(
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: http_serde::query::prepare::Request,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;
    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(req.origin),
        payload: TransportCommand::Query(QueryCommand::Prepare(req.data, tx)),
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
