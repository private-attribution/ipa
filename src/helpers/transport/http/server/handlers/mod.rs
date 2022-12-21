mod create_query;
mod echo;
mod mul;
mod network_event;
mod prepare_query;
mod start_mul;

use crate::{
    helpers::transport::TransportCommand,
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use axum::Router;
use std::collections::HashMap;
use tokio::sync::mpsc;

pub fn router(
    transport_sender: mpsc::Sender<TransportCommand>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
) -> Router {
    echo::router()
        .merge(create_query::router(transport_sender.clone()))
        .merge(prepare_query::router(transport_sender.clone()))
        .merge(start_mul::router(transport_sender.clone()))
        .merge(mul::router(transport_sender))
        .merge(network_event::router(ongoing_queries))
}
