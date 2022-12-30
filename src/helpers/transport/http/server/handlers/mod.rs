mod create_query;
mod echo;
mod prepare_query;
mod query_input;
mod query_results;
mod step;

use crate::{
    ff::FieldType,
    helpers::{
        query::{QueryConfig, QueryType},
        transport::http::server::Error,
        CommandEnvelope,
    },
    protocol::QueryId,
    sync::{Arc, Mutex},
};
use async_trait::async_trait;
use axum::extract::{FromRequest, Query, RequestParts};
use axum::Router;
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
                panic!("don't know how to construct IPA query type yet");
            }
            other => Err(Error::bad_query_value("query_type", other)),
        }?;
        Ok(QueryConfigFromReq(QueryConfig {
            field_type,
            query_type,
        }))
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
