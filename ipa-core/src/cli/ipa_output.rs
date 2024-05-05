use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::helpers::query::{IpaQueryConfig, QuerySize};

#[derive(Debug, Serialize, Deserialize)]
pub struct QueryResult {
    pub input_size: QuerySize,
    pub config: IpaQueryConfig,
    #[serde(
        serialize_with = "crate::serde::duration::to_secs",
        deserialize_with = "crate::serde::duration::from_secs"
    )]
    pub latency: Duration,
    pub breakdowns: Vec<u32>,
}
