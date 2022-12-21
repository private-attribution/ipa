use crate::{
    helpers::transport::{http::server::Error, MulData, TransportCommand},
    net::ByteArrStream,
    protocol::QueryId,
};
use axum::{
    extract::{Path, Query, RequestParts},
    routing::post,
    Extension, Router,
};
use hyper::{Body, Request};
use tokio::sync::mpsc;

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct MulParams {
    field_type: String,
}

async fn handler(
    query_id: Path<QueryId>,
    params: Query<MulParams>,
    transport_sender: Extension<mpsc::Sender<TransportCommand>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let data_stream = RequestParts::new(req)
        .extract::<ByteArrStream>()
        .await
        .map_err(|_| {
            Error::BadQueryString("TODO: move ByteArrStream to the right package".into())
        })?;

    let data = MulData {
        query_id: *query_id,
        field_type: params.0.field_type,
        data_stream,
    };
    permit.send(TransportCommand::Mul(data));
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<TransportCommand>) -> Router {
    Router::new()
        .route("/query/:query_id/mul", post(handler))
        .layer(Extension(transport_sender))
}
