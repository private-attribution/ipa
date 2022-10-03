use crate::cli::net::server::MpcServerError;
use crate::cli::net::{BufferedMessages, RecordHeaders};
use crate::protocol::{QueryId, Step};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{self, FromRequest, RequestParts};
use tokio::sync::mpsc;

pub struct Path<S: Step>(QueryId, S);
#[async_trait]
impl<B: Send, S: Step> FromRequest<B> for Path<S> {
    type Rejection = MpcServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extract::Path((query_id, step)) =
            extract::Path::<(QueryId, String)>::from_request(req).await?;
        let step = S::try_from(step).map_err::<serde_json::Error, _>(serde::de::Error::custom)?;
        Ok(Path(query_id, step))
    }
}

pub async fn handler<S: Step>(
    outgoing: mpsc::Sender<BufferedMessages<S>>,
    Path(query_id, step): Path<S>,
    RecordHeaders { offset, data_size }: RecordHeaders,
    body: Bytes,
) -> Result<(), MpcServerError> {
    println!(
        "{:?} {:?} {:?}, {:?}, {:?}",
        query_id, step, offset, data_size, body
    );
    outgoing
        .send(BufferedMessages {
            query_id,
            step,
            offset,
            data_size,
            body,
        })
        .await?;
    Ok(())
}
