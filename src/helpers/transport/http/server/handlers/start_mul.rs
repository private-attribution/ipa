use crate::{
    helpers::transport::{http::server::Error, StartMulData, TransportCommand},
    net::ByteArrStream,
    protocol::QueryId,
};
use axum::{
    extract::{Path, RequestParts},
    routing::post,
    Extension, Router,
};
use hyper::{Body, Request};
use tokio::sync::{mpsc, oneshot};

async fn handler(
    query_id: Path<QueryId>,
    transport_sender: Extension<mpsc::Sender<TransportCommand>>,
    req: Request<Body>,
) -> Result<(), Error> {
    let permit = transport_sender.reserve().await?;

    let data_stream = RequestParts::new(req)
        .extract::<ByteArrStream>()
        .await
        .map_err(|_| {
            Error::BadQueryString("FIXME: move ByteArrStream to the right package".into())
        })?;

    let (tx, rx) = oneshot::channel();
    let data = StartMulData::new(*query_id, data_stream, tx);
    permit.send(TransportCommand::StartMul(data));

    rx.await?;
    Ok(())
}

pub fn router(transport_sender: mpsc::Sender<TransportCommand>) -> Router {
    Router::new()
        .route("/query/:query_id/start-mul", post(handler))
        .layer(Extension(transport_sender))
}
