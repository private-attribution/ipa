mod create_query;
mod echo;
mod prepare_query;
mod query_input;
mod query_results;
mod step;

use crate::{
    ff::FieldType,
    helpers::{
        query::{IPAQueryConfig, QueryConfig, QueryType},
        transport::ByteArrStream,
        CommandEnvelope,
    },
    http::server::Error,
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

struct QueryConfigFromReq(QueryConfig);

#[cfg(feature = "enable-serde")]
#[async_trait]
impl<B: Send> FromRequest<B> for QueryConfigFromReq {
    type Rejection = Error;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        #[derive(serde::Deserialize)]
        struct QueryTypeParam {
            field_type: FieldType,
            query_type: String,
        }
        let Query(QueryTypeParam {
            field_type,
            query_type,
        }) = req.extract().await?;
        let query_type = match query_type.as_str() {
            #[cfg(any(test, feature = "cli", feature = "test-fixture"))]
            QueryType::TEST_MULTIPLY_STR => Ok(QueryType::TestMultiply),
            QueryType::IPA_STR => {
                // TODO: these are hard-coded, but should be retrieved from the request
                Ok(QueryType::IPA(IPAQueryConfig {
                    num_bits: 20,
                    per_user_credit_cap: 3,
                    max_breakdown_key: 3,
                }))
            }
            other => Err(Error::bad_query_value("query_type", other)),
        }?;
        Ok(QueryConfigFromReq(QueryConfig {
            field_type,
            query_type,
        }))
    }
}

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

        let Query(FieldTypeParam { field_type }) = req.extract().await?;
        let body: BodyStream = req.extract().await?;
        // TODO: multiply the field_type by 22; this is a hacky way of making sure IPA can run,
        //       since `IPAInputRow` is 22 bytes when using `Fp31`. Fix this later to be way less
        //       hacky.
        let bas = ByteArrStream::new(body, field_type.size_in_bytes() * 22);
        Ok(ByteArrStreamFromReq(bas))
    }
}

// TODO: move all query handlers to query sub folder
pub fn router(
    transport_sender: mpsc::Sender<CommandEnvelope>,
    // TODO: clean up after query has been processed
    ongoing_queries: Arc<Mutex<HashMap<QueryId, mpsc::Sender<CommandEnvelope>>>>,
) -> Router {
    echo::router()
        .merge(create_query::router(transport_sender.clone()))
        .merge(prepare_query::router(transport_sender.clone()))
        .merge(query_input::router(transport_sender.clone()))
        .merge(query_results::router(transport_sender))
        .merge(step::router(ongoing_queries))
}
