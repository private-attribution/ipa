use crate::helpers::query::{IpaQueryConfig, QuerySize};
use std::time::Duration;

#[derive(Debug)]
#[cfg_attr(feature = "enable-serde", derive(serde::Serialize, serde::Deserialize))]
pub struct QueryResult {
    pub input_size: QuerySize,
    pub config: IpaQueryConfig,
    #[serde(
        serialize_with = "duration_to_secs",
        deserialize_with = "secs_to_duration"
    )]
    pub latency: Duration,
    pub breakdowns: Vec<u32>,
}

#[cfg(feature = "enable-serde")]
pub fn duration_to_secs<S: serde::Serializer>(d: &Duration, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_f64(d.as_secs_f64())
}

#[cfg(feature = "enable-serde")]
pub fn secs_to_duration<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Duration, D::Error> {
    let secs = serde::Deserialize::deserialize(d)?;
    Ok(Duration::from_secs_f64(secs))
}
