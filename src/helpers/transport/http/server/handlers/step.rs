use crate::helpers::transport::http::StepHeaders;
use crate::{
    helpers::{
        network::ChannelId,
        transport::{
            http::{server::Error, StepBody},
            StepData, TransportCommand,
        },
        Role,
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
struct StepParams {
    role: Role,
}

fn ensure_ordering(
    ongoing_offset: &Arc<Mutex<HashMap<(QueryId, ChannelId), u32>>>,
    key: &(QueryId, ChannelId),
    next_seen: u32,
) {
    let blow_up = |last_seen| {
        panic!("out-of-order delivery of data for query:{}, role:{}, step:{}: expected index {last_seen}, but found {next_seen}", key.0.as_ref(), key.1.role.as_ref(), key.1.step.as_ref())
    };

    let mut ongoing_offset = ongoing_offset.lock().unwrap();
    match ongoing_offset.get_mut(key) {
        Some(last_seen) if *last_seen == next_seen => {
            *last_seen += 1;
        }
        Some(last_seen) => blow_up(*last_seen),
        None if next_seen != 0 => blow_up(0),
        None => {}
    }
}

#[allow(clippy::type_complexity)] // it's a hashmap
async fn handler(
    query_id: Path<(QueryId, Step)>,
    sp: Query<StepParams>,
    sh: StepHeaders,
    ongoing_queries: Extension<Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>>,
    ongoing_offset: Extension<Arc<Mutex<HashMap<(QueryId, ChannelId), u32>>>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let Path((query_id, step)) = query_id;
    let Query(StepParams { role }) = sp;
    let channel_id = ChannelId::new(role, step);

    let key = (query_id, channel_id);
    ensure_ordering(&ongoing_offset.0, &key, sh.offset);
    let (query_id, channel_id) = key;

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

    let Json(StepBody {
        roles_to_helpers,
        chunk,
    }) = RequestParts::new(req).extract().await?;

    let data = StepData {
        query_id,
        roles_to_helpers,
        message_chunks: (channel_id, chunk),
        offset: sh.offset,
    };
    permit.send(TransportCommand::Step(data));
    Ok(())
}

pub fn router(
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<TransportCommand>>>>,
    ongoing_offset: Arc<Mutex<HashMap<(QueryId, ChannelId), u32>>>,
) -> Router {
    Router::new()
        .route("/query/:query_id/step/:step", post(handler))
        .layer(Extension(ongoing_queries))
        .layer(Extension(ongoing_offset))
}
