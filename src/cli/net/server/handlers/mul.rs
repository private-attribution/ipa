use crate::cli::net::server::MpcServerError;
use crate::cli::net::MessageEnvelope;
use crate::helpers::mesh::Message;
use crate::protocol::{QueryId, Step};
use axum::body::Bytes;
use axum::extract::Path;
use hyper::Body;
use serde::Deserializer;

#[cfg_attr(
    feature = "enable-serde",
    derive(serde::Deserialize),
    serde(try_from = "String")
)]
struct PathStep<S: Step>(S);
impl<S: Step> TryFrom<String> for PathStep<S> {
    type Error = crate::error::Error;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(PathStep(S::try_from(value)?))
    }
}

pub async fn handler<S: Step>(
    // TODO: still not working
    Path((query_id, PathStep(step))): Path<(QueryId, PathStep<S>)>,
    // Path((query_id, step)): Path<(QueryId, String)>,
    body: Bytes,
) -> Result<(), MpcServerError> {
    println!("received step {:?} with body {:?}", step, body);
    Ok(())
}

// pub async fn handler<S: Step, M: Message>(req: Request<Body>) -> Result<(), MpcServerError> {
//     let (parts, body) = req.into_parts();
//     let body = serde_json::from_slice::<Vec<MessageEnvelope<M>>>(&body::to_bytes(body).await?)?;
//     println!("received parts {:?} with body {:?}", parts, body);
//     Ok(())
// }
