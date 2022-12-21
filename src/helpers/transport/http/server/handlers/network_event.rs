use crate::{
    helpers::{
        network::ChannelId,
        transport::{http::server::Error, NetworkEventData, TransportCommand},
        HelperIdentity, Role,
    },
    protocol::{QueryId, Step},
    sync::{Arc, Mutex},
};
use axum::{
    extract::{Path, Query, RequestParts},
    routing::post,
    Extension, Json, Router,
};
use hyper::{Body, Request};
use std::collections::HashMap;
use tokio::sync::mpsc;

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct NetworkEventParams {
    role: Role,
    step: Step,
}

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct NetworkEventBody {
    roles_to_helpers: [HelperIdentity; 3],
    chunk: Vec<u8>,
}

#[allow(clippy::type_complexity)] // it's a hashmap
async fn handler(
    query_id: Path<QueryId>,
    nep: Query<NetworkEventParams>,
    ongoing_queries: Extension<Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let query_id = *query_id;
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

    let Json(NetworkEventBody {
        roles_to_helpers,
        chunk,
    }) = RequestParts::new(req).extract().await?;
    let Query(NetworkEventParams { role, step }) = nep;
    let channel_id = ChannelId::new(role, step);
    let message_chunks = (channel_id, chunk);

    let data = NetworkEventData {
        query_id,
        roles_to_helpers,
        message_chunks,
    };
    permit.send(TransportCommand::NetworkEvent(data));
    Ok(())
}

pub fn router(
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
) -> Router {
    Router::new()
        .route("/query/:query_id/network-event", post(handler))
        .layer(Extension(ongoing_queries))
}
