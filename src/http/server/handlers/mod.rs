mod echo;
mod query;

use crate::{
    ff::FieldType,
    helpers::{transport::ByteArrStream, CommandEnvelope},
    http::{http_serde, server::Error},
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use async_trait::async_trait;
use axum::extract::BodyStream;
use axum::{
    extract::{FromRequest, Query, RequestParts},
    Router,
};
use hyper::body::{Bytes, HttpBody};
use std::collections::HashMap;
use tokio::sync::mpsc;

struct ByteArrStreamFromReq(ByteArrStream);

#[cfg(feature = "enable-serde")]
#[async_trait]
impl<B: HttpBody<Data = Bytes, Error = hyper::Error> + Send + 'static> FromRequest<B>
    for ByteArrStreamFromReq
{
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        #[derive(serde::Deserialize)]
        struct FieldTypeParam {
            field_type: FieldType,
        }

        // TODO: don't use `field_type` here. we need to use `size_in_bytes`, and possibly defer
        //       defer this decision to query processing layer
        let Query(FieldTypeParam { field_type }) = req.extract().await?;
        let body: BodyStream = req.extract().await?;
        let bas = ByteArrStream::new(body, field_type.size_in_bytes());
        Ok(ByteArrStreamFromReq(bas))
    }
}

pub fn router(
    transport_sender: mpsc::Sender<CommandEnvelope>,
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    echo::router().nest(
        http_serde::BASE_QUERY_AXUM_PATH,
        query::router(transport_sender, ongoing_queries),
    )
}
