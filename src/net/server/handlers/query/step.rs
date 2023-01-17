use crate::{
    helpers::{transport::TransportCommand, CommandEnvelope, CommandOrigin},
    net::{http_serde, server::Error},
    protocol::{QueryId, Step},
    sync::{Arc, Mutex},
};
use axum::{extract::Path, routing::post, Extension, Router};
use hyper::{body, Body, Request};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[allow(clippy::type_complexity)] // it's a hashmap
async fn handler(
    query_id: Path<(QueryId, Step)>,
    origin_header: http_serde::query::OriginHeader,
    step_headers: http_serde::query::step::Headers,
    ongoing_queries: Extension<Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let Path((query_id, step)) = query_id;

    // wrap in braces to ensure lock is released
    let network_sender = {
        ongoing_queries
            .lock()
            .unwrap()
            .get(&query_id)
            .ok_or_else(|| Error::query_id_not_found(query_id))?
            .clone()
    };
    let permit = network_sender.reserve().await?;

    let payload = body::to_bytes(req.into_body()).await?.to_vec();

    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(origin_header.origin),
        payload: TransportCommand::StepData {
            query_id,
            step,
            payload,
            offset: step_headers.offset,
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
