use crate::cli::net::server::MpcServerError;
use crate::cli::net::MessageEnvelope;
use crate::protocol::{QueryId, Step};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::extract::{self, FromRequest, RequestParts};
// use tokio::sync::mpsc::Sender;

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

type BufferedMessages<S> = (QueryId, S, Vec<MessageEnvelope>);

pub struct Handler<S: Step> {
    // outgoing: Sender<BufferedMessages<S>>,
    _phantom: std::marker::PhantomData<S>,
}

impl<S: Step> Handler<S> {
    // pub fn new(outgoing: Sender<BufferedMessages<S>>) -> Self {
    //     Self { outgoing }
    // }
    pub fn new() -> Self {
        Self {
            _phantom: std::marker::PhantomData::default(),
        }
    }

    pub async fn handler(
        &self,
        Path(query_id, step): Path<S>,
        body: Bytes,
    ) -> Result<(), MpcServerError> {
        // self.outgoing.send((query_id, step, body)).await?;
        println!("{:?} {:?} {:?}", query_id, step, body);
        Ok(())
    }
}

pub async fn handler<S: Step>(
    Path(query_id, step): Path<S>,
    body: Bytes,
) -> Result<(), MpcServerError> {
    println!("{:?} {:?} {:?}", query_id, step, body);
    Ok(())
}
