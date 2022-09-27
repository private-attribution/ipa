use crate::cli::net::server::MpcServerError;
use crate::cli::net::MessageEnvelope;
use crate::error::BoxError;
use crate::helpers::mesh::Message;
use crate::protocol::{QueryId, Step};
use axum::body::Bytes;
use axum::extract::Path;
use hyper::Body;
use serde::Deserializer;

/// TODO: is this the correct direction?
// alternative one
// #[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
// struct PathStep<S: Step>(#[serde(deserialize_with = "deserialize_via_try_from")] S);
//
// fn deserialize_via_try_from<'de, D: Deserializer<'de>, S: Step>(d: D) -> Result<S, D::Error> {
//     use serde::de::{Deserialize, Deserializer};
//     use std::str::FromStr;
//     let str = String::deserialize(d)?;
//     S::try_from(str).map_err(serde::de::Error::custom)
// }

// alternative two
#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(try_from = "String")
)]
struct PathStep<S: Step>(S);
impl<S: Step> TryFrom<String> for PathStep<S> {
    type Error = BoxError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(PathStep(S::try_from(value)?))
    }
}

pub async fn handler<S: Step, M: Message>(
    Path((query_id, PathStep(step))): Path<(QueryId, PathStep<S>)>,
    body: Bytes,
) -> Result<(), MpcServerError> {
    let body = serde_json::from_slice::<Vec<MessageEnvelope<M>>>(&body)?;
    println!("received step {:?} with body {:?}", step, body);
    Ok(())
}

// pub async fn handler<S: Step, M: Message>(req: Request<Body>) -> Result<(), MpcServerError> {
//     let (parts, body) = req.into_parts();
//     let body = serde_json::from_slice::<Vec<MessageEnvelope<M>>>(&body::to_bytes(body).await?)?;
//     println!("received parts {:?} with body {:?}", parts, body);
//     Ok(())
// }
