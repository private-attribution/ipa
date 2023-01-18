use crate::{
    helpers::{transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::{routing::post, Extension, Router};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[allow(clippy::type_complexity)] // it's a hashmap
async fn handler(
    req: http_serde::query::step::Request,
    ongoing_queries: Extension<Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>>,
) -> Result<(), Error> {
    // wrap in braces to ensure lock is released
    let network_sender = {
        ongoing_queries
            .lock()
            .unwrap()
            .get(&req.query_id)
            .ok_or_else(|| Error::query_id_not_found(req.query_id))?
            .clone()
    };
    let permit = network_sender.reserve().await?;

    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(req.origin),
        payload: TransportCommand::StepData {
            query_id: req.query_id,
            step: req.step,
            payload: req.payload,
            offset: req.offset,
        },
    };
    permit.send(command);
    Ok(())
}

pub fn router(
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    Router::new()
        .route(http_serde::query::step::AXUM_PATH, post(handler))
        .layer(Extension(ongoing_queries))
}
