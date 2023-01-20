use crate::{
    helpers::{query::QueryCommand, transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
};
use axum::{routing::post, Extension, Json, Router};
use tokio::sync::{mpsc, oneshot};

/// Takes details from the HTTP request and creates a `[TransportCommand]::CreateQuery` that is sent
/// to the [`HttpTransport`].
async fn handler(
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: http_serde::query::create::Request,
) -> Result<Json<http_serde::query::create::ResponseBody>, Error> {
    let permit = transport_sender.reserve().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();

    // send command, receive response
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Create(req.query_config, tx)),
    };
    permit.send(command);
    let query_id = rx.await?;

    Ok(Json(http_serde::query::create::ResponseBody { query_id }))
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route(http_serde::query::create::AXUM_PATH, post(handler))
        .layer(Extension(transport_sender))
}
