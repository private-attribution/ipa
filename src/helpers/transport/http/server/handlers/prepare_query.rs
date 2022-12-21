use crate::{
    helpers::transport::{
        http::{server::Error, PrepareQueryBody, PrepareQueryParams},
        PrepareQueryData, TransportCommand,
    },
    protocol::QueryId,
};
use axum::{
    extract::{Path, RequestParts},
    http::Request,
    routing::post,
    Extension, Json, Router,
};
use hyper::Body;
use tokio::sync::{mpsc, oneshot};

async fn handler(
    query_id: Path<QueryId>,
    params: PrepareQueryParams,
    transport_sender: Extension<mpsc::Sender<TransportCommand>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let Json(PrepareQueryBody {
        helper_positions,
        helpers_to_roles,
    }) = RequestParts::new(req).extract().await?;

    // prepare command data
    let (tx, rx) = oneshot::channel();
    let data = PrepareQueryData::new(
        *query_id,
        params.field_type,
        helper_positions,
        helpers_to_roles,
        tx,
    );
    permit.send(TransportCommand::PrepareQuery(data));

    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<TransportCommand>) -> Router {
    Router::new()
        .route("query/:query_id", post(handler))
        .layer(Extension(transport_sender))
}
