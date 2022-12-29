use crate::{
    helpers::{
        query::{PrepareQuery, QueryCommand, QueryConfig},
        transport::{
            http::{server::Error, OriginHeader, PrepareQueryBody, PrepareQueryParams},
            TransportCommand,
        },
        CommandEnvelope, CommandOrigin,
    },
    protocol::QueryId,
};
use axum::{
    extract::{Path, Query, RequestParts},
    http::Request,
    routing::post,
    Extension, Json, Router,
};
use hyper::Body;
use tokio::sync::{mpsc, oneshot};

async fn handler(
    query_id: Path<QueryId>,
    params: Query<PrepareQueryParams>,
    origin_header: OriginHeader,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let Json(PrepareQueryBody { roles }) = RequestParts::new(req).extract().await?;

    let data = PrepareQuery {
        query_id: *query_id,
        config: QueryConfig {
            field_type: params.0.field_type,
            query_type: params.0.query_type,
        },
        roles,
    };
    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Helper(origin_header.origin),
        payload: TransportCommand::Query(QueryCommand::Prepare(data, tx)),
    };
    permit.send(command);

    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route("query/:query_id", post(handler))
        .layer(Extension(transport_sender))
}
