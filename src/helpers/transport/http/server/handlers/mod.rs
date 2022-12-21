mod create_query;
mod echo;
mod prepare_query;

use crate::helpers::transport::TransportCommand;
use axum::Router;
use tokio::sync::mpsc;

pub fn router(transport_sender: mpsc::Sender<TransportCommand>) -> Router {
    echo::router()
        .merge(create_query::router(transport_sender.clone()))
        .merge(prepare_query::router(transport_sender))
}
