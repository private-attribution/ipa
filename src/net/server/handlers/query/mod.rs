mod create;
mod input;
mod prepare;
mod results;
mod step;

use crate::{
    helpers::CommandEnvelope,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::Router;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub fn router(
    transport_sender: mpsc::Sender<CommandEnvelope>,
    // TODO: clean up after query has been processed
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    Router::new()
        .merge(create::router(transport_sender.clone()))
        .merge(prepare::router(transport_sender.clone()))
        .merge(input::router(transport_sender.clone()))
        .merge(results::router(transport_sender))
        .merge(step::router(ongoing_queries))
}
