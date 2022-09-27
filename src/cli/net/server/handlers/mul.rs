use crate::cli::net::server::MpcServerError;
use crate::cli::net::MessageEnvelope;
use crate::helpers::mesh::Message;
use crate::protocol::Step;
use axum::http::Request;
use hyper::{body, Body};

// TODO: why won't this work?
// pub async fn handler<S: Step, M: Message>(
//     Path((query_id, step)): Path<(QueryId, S)>,
//     body: Body,
// ) -> Result<(), MpcServerError> {
//     let body =
//         serde_json::from_slice::<Vec<MessageEnvelope<M>>>(&body::to_bytes(body).await?.to_vec())?;
//     println!("received step {:?} with body {:?}", pe.step, body);
//     Ok(())
// }

pub async fn handler<S: Step, M: Message>(req: Request<Body>) -> Result<(), MpcServerError> {
    let (parts, body) = req.into_parts();
    let body = serde_json::from_slice::<Vec<MessageEnvelope<M>>>(&body::to_bytes(body).await?)?;
    println!("received parts {:?} with body {:?}", parts, body);
    Ok(())
}
