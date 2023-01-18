use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::post, Extension, Router};
use tokio::sync::{mpsc, oneshot};

async fn handler(
    req: http_serde::query::input::Request,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Input(req.query_input, tx)),
    };
    permit.send(command);
    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::input::AXUM_PATH, post(handler))
        .layer(Extension(transport_sender))
}
