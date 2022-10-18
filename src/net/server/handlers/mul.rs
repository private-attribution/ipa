use crate::helpers::fabric::{ChannelId, MessageChunks, MessageEnvelope};
use crate::helpers::Identity;
use crate::net::server::MpcServerError;
use crate::net::{BufferedMessages, RecordHeaders};
use crate::protocol::{IPAProtocolStep, QueryId, RecordId, Step};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{self, FromRequest, Query, RequestParts},
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
    Extension,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Used in the axum handler to extract the `query_id` and `step` from the path of the request
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

/// TODO: implement receiver
#[derive(Clone)]
pub struct MessageStreamExt<S> {
    sender: mpsc::Sender<MessageChunks<S>>,
}
impl<S: Step> MessageStreamExt<S> {
    /// TODO: replace with real implementation
    pub fn example() -> Self {
        let (tx, _) = mpsc::channel(1);
        Self { sender: tx }
    }
}

/// Injects a permit to send data to the message layer into the Axum request, so that downstream
/// handlers have simple access to the correct value
///
/// For now, stub out the permit logic with just an empty channel
pub async fn upstream_middleware_fn<B: Send, S: Step>(
    message_stream: MessageStreamExt<S>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, MpcServerError> {
    let permit = message_stream.sender.reserve_owned().await?;

    let mut req_parts = RequestParts::new(req);
    req_parts.extensions_mut().insert(permit);

    let req = req_parts.try_into_request()?;

    Ok(next.run(req).await)
}

#[axum_macros::debug_handler]
/// accepts all the relevant information from the request, and push all of it onto the gateway
pub async fn handler(
    Extension(permit): Extension<mpsc::OwnedPermit<MessageChunks<IPAProtocolStep>>>,
    Path(_query_id, step): Path<IPAProtocolStep>,
    Query(identity): Query<Identity>,
    RecordHeaders { offset, data_size }: RecordHeaders,
    body: Bytes,
) -> Result<(), MpcServerError> {
    let channel_id = ChannelId {
        identity: Identity::H1,
        step,
    };
    let envelopes = body
        .as_ref()
        .chunks(data_size as usize)
        .enumerate()
        .map(|(record_id, chunk)| MessageEnvelope {
            record_id: RecordId::from(offset + record_id as u32),
            payload: chunk.to_vec().into_boxed_slice(),
        })
        .collect::<Vec<_>>();

    permit.send((channel_id, envelopes));
    Ok(())
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::net::mpc_helper_router;
//     use crate::protocol::IPAProtocolStep;
//     use axum::http::{Request, StatusCode};
//     use axum_server::service::SendService;
//     use hyper::{body, Body};
//     use tower::ServiceExt;
//
//     fn build_req<S: Step>(
//         query_id: QueryId,
//         step: S,
//         offset: u32,
//         data_size: u32,
//         body: &'static [u8],
//     ) -> Request<Body> {
//         assert_eq!(
//             body.len() % (data_size as usize),
//             0,
//             "body len must align with data_size"
//         );
//         let uri = format!(
//             "http://localhost:3000/mul/query-id/{}/step/{}",
//             query_id, step
//         );
//         let headers = RecordHeaders {
//             offset,
//             data_size: data_size as u32,
//         };
//         let body = Body::from(Bytes::from_static(body));
//         headers
//             .add_to(Request::post(uri))
//             .body(body)
//             .expect("request should be valid")
//     }
//
//     fn init_gateway_map<S: Step>(
//         query_id: QueryId,
//         step: S,
//     ) -> (GatewayMap<S>, mpsc::Receiver<BufferedMessages<S>>) {
//         let mut m = HashMap::with_capacity(1);
//         let (tx, rx) = mpsc::channel(1);
//         m.insert((query_id, step), tx);
//         (Arc::new(Mutex::new(m)), rx)
//     }

//     #[tokio::test]
//     async fn collect_req() {
//         const DATA_SIZE: u32 = 4;
//         let query_id = QueryId;
//         let step = IPAProtocolStep::ConvertShares;
//         let offset = 0;
//         let body = &[0; 3 * DATA_SIZE as usize];
//
//         let req = build_req(query_id, step, offset, DATA_SIZE, body);
//         let (m, mut rx) = init_gateway_map(query_id, step);
//         let service = mpc_helper_router::<IPAProtocolStep>(m).into_service();
//         let resp = service.oneshot(req).await.unwrap();
//         let status = resp.status();
//         let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
//         let resp_body_str = String::from_utf8_lossy(&resp_body);
//
//         assert_eq!(status, StatusCode::OK, "{}", resp_body_str);
//         let messages = rx.try_recv().expect("should have already received value");
//         assert_eq!(
//             messages,
//             BufferedMessages {
//                 query_id,
//                 step,
//                 offset,
//                 data_size: DATA_SIZE as u32,
//                 body: Bytes::from_static(body),
//             }
//         );
//     }
//
//     #[tokio::test]
//     async fn error_on_missing_gateway() {
//         const DATA_SIZE: u32 = 4;
//         let query_id = QueryId;
//         let step = IPAProtocolStep::ConvertShares;
//         let offset = 0;
//         let body = &[0; 3 * DATA_SIZE as usize];
//
//         let req = build_req(query_id, step, offset, DATA_SIZE, body);
//         let empty_m = Arc::new(Mutex::new(HashMap::new()));
//         let service = mpc_helper_router::<IPAProtocolStep>(empty_m).into_service();
//         let resp = service.oneshot(req).await.unwrap();
//         let status = resp.status();
//         let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
//         let resp_body_str = String::from_utf8_lossy(&resp_body);
//         assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", resp_body_str);
//     }
// }
