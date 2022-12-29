use crate::{
    ff::FieldType,
    helpers::{
        query::{QueryCommand, QueryInput},
        transport::{http::server::Error, TransportCommand},
        CommandEnvelope, CommandOrigin,
    },
    net::ByteArrStream,
    protocol::QueryId,
};
use axum::{
    extract::{Path, Query, RequestParts},
    routing::post,
    Extension, Router,
};
use futures::Stream;
use futures_util::TryStreamExt;
use hyper::{Body, Request};
use std::pin::Pin;
use tokio::sync::{mpsc, oneshot};
use crate::helpers::TransportError;

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct InputParams {
    field_type: FieldType,
}

async fn handler(
    query_id: Path<QueryId>,
    params: Query<InputParams>,
    transport_sender: Extension<mpsc::Sender<CommandEnvelope>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let input_stream = RequestParts::new(req)
        .extract::<ByteArrStream>()
        .await
        .map_err(|_| Error::BadQueryString("TODO: move ByteArrStream to the right package".into()))?
        .and_then(|bytes| futures::future::ok(bytes.to_vec()))
        .map_err(TransportError::from);
    let query_input = QueryInput {
        query_id: *query_id,
        field_type: params.field_type,
        input_stream: Box::pin(input_stream)
            as Pin<Box<dyn Stream<Item = Result<Vec<u8>, TransportError>> + Send>>,
    };
    let (tx, rx) = oneshot::channel();
    let command = CommandEnvelope {
        origin: CommandOrigin::Other,
        payload: TransportCommand::Query(QueryCommand::Input(query_input, tx)),
    };
    permit.send(command);
    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<CommandEnvelope>) -> Router {
    Router::new()
        .route("/query/:query_id/input", post(handler))
        .layer(Extension(transport_sender))
}
