mod create_query;
mod prepare_query;
mod query_input;
mod query_results;
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
        .merge(create_query::router(transport_sender.clone()))
        .merge(prepare_query::router(transport_sender.clone()))
        .merge(query_input::router(transport_sender.clone()))
        .merge(query_results::router(transport_sender))
        .merge(step::router(ongoing_queries))
}
