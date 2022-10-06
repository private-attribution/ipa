use crate::net::server::MpcServerError;
use crate::net::{BufferedMessages, RecordHeaders};
use crate::protocol::{QueryId, Step};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{self, FromRequest, RequestParts},
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Extension,
};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;
use tracing::log::debug;

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

pub type GatewayMap<S> = Arc<Mutex<HashMap<(QueryId, S), mpsc::Sender<BufferedMessages<S>>>>>;

/// Injects the appropriate gateway/mesh into the Axum request, so that downstream handlers have
/// simple access to the correct value
///
/// For now, stub out the gateway/mesh logic with just a channel
/// TODO: if request asks for gateway that does not exist, should it add the gateway, or should
///       it fail? who is responsible for managing the existence of gateways?
pub async fn gateway_middleware_fn<B: Send, S: Step>(
    gateway_map: GatewayMap<S>,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, StatusCode> {
    let mut req_parts = RequestParts::new(req);
    let Path(query_id, step) = Path::<S>::from_request(&mut req_parts)
        .await
        .map_err(|err| err.into_response().status())?;

    let gateway = gateway_map
        .lock()
        .unwrap()
        .get(&(query_id, step))
        .map_or(Err(StatusCode::BAD_REQUEST), |gw| Ok(gw.clone()))?;

    let ousted = req_parts.extensions_mut().insert(gateway);
    if ousted.is_some() {
        debug!(
            "ousted existing entry in gateway map: ({}, {})",
            query_id, step
        );
    }

    let req = req_parts
        .try_into_request()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    Ok(next.run(req).await)
}

/// accepts all the relevant information from the request, and push all of it onto the `outgoing`
/// channel
/// TODO: implement the receiving end of `outgoing`
pub async fn handler<S: Step>(
    Extension(outgoing): Extension<mpsc::Sender<BufferedMessages<S>>>,
    Path(query_id, step): Path<S>,
    RecordHeaders { offset, data_size }: RecordHeaders,
    body: Bytes,
) -> Result<(), MpcServerError> {
    outgoing
        .send(BufferedMessages {
            query_id,
            step,
            offset,
            data_size,
            body,
        })
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mpc_helper_router;
    use crate::protocol::IPAProtocolStep;
    use axum::http::{Request, StatusCode};
    use axum_server::service::SendService;
    use hyper::{body, Body};
    use tower::ServiceExt;

    fn build_req<S: Step>(
        query_id: QueryId,
        step: S,
        offset: u32,
        data_size: u32,
        body: &'static [u8],
    ) -> Request<Body> {
        assert_eq!(
            body.len() % (data_size as usize),
            0,
            "body len must align with data_size"
        );
        let uri = format!(
            "http://localhost:3000/mul/query-id/{}/step/{}",
            query_id, step
        );
        let headers = RecordHeaders {
            offset,
            data_size: data_size as u32,
        };
        let body = Body::from(Bytes::from_static(body));
        headers
            .add_to(Request::post(uri))
            .body(body)
            .expect("request should be valid")
    }

    fn init_gateway_map<S: Step>(
        query_id: QueryId,
        step: S,
    ) -> (GatewayMap<S>, mpsc::Receiver<BufferedMessages<S>>) {
        let mut m = HashMap::with_capacity(1);
        let (tx, rx) = mpsc::channel(1);
        m.insert((query_id, step), tx);
        (Arc::new(Mutex::new(m)), rx)
    }

    #[tokio::test]
    async fn collect_req() {
        const DATA_SIZE: u32 = 4;
        let query_id = QueryId;
        let step = IPAProtocolStep::ConvertShares;
        let offset = 0;
        let body = &[0; 3 * DATA_SIZE as usize];

        let req = build_req(query_id, step, offset, DATA_SIZE, body);
        let (m, mut rx) = init_gateway_map(query_id, step);
        let service = mpc_helper_router::<IPAProtocolStep>(m).into_service();
        let resp = service.oneshot(req).await.unwrap();
        let status = resp.status();
        let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body_str = String::from_utf8_lossy(&resp_body);

        assert_eq!(status, StatusCode::OK, "{}", resp_body_str);
        let messages = rx.try_recv().expect("should have already received value");
        assert_eq!(
            messages,
            BufferedMessages {
                query_id,
                step,
                offset,
                data_size: DATA_SIZE as u32,
                body: Bytes::from_static(body),
            }
        );
    }

    #[tokio::test]
    async fn error_on_missing_gateway() {
        const DATA_SIZE: u32 = 4;
        let query_id = QueryId;
        let step = IPAProtocolStep::ConvertShares;
        let offset = 0;
        let body = &[0; 3 * DATA_SIZE as usize];

        let req = build_req(query_id, step, offset, DATA_SIZE, body);
        let empty_m = Arc::new(Mutex::new(HashMap::new()));
        let service = mpc_helper_router::<IPAProtocolStep>(empty_m).into_service();
        let resp = service.oneshot(req).await.unwrap();
        let status = resp.status();
        let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body_str = String::from_utf8_lossy(&resp_body);
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {}", resp_body_str);
    }
}
