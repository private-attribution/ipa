mod echo;
mod query;

use crate::{
    helpers::CommandEnvelope,
    net::http_serde,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::Router;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub fn router(
    transport_sender: mpsc::Sender<CommandEnvelope>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    echo::router().nest(
        http_serde::query::BASE_AXUM_PATH,
        query::router(transport_sender, ongoing_queries),
    )
}
