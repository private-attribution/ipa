use crate::helpers::network::{ChannelId, MessageChunks};
use crate::helpers::Role;
use crate::net::server::{MessageSendMap, MpcHelperServerError};
use crate::net::RecordHeaders;
use crate::protocol::{QueryId, UniqueStepId};
use async_trait::async_trait;
use axum::extract::{self, FromRequest, Query, RequestParts};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use hyper::Body;

use tokio::sync::mpsc;

/// Used in the axum handler to extract the `query_id` and `step` from the path of the request
pub struct Path(QueryId, UniqueStepId);

#[async_trait]
impl<B: Send> FromRequest<B> for Path {
    type Rejection = MpcHelperServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extract::Path((query_id, step)) =
            extract::Path::<(QueryId, UniqueStepId)>::from_request(req).await?;
        Ok(Path(query_id, step))
    }
}

/// Used in the axum handler to extract the peer role from the query params of the request
#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
pub struct RoleQueryParam {
    role: Role,
}

/// After an [`OwnedPermit`] has been reserved, it can be used once to send an item on the channel.
///
/// Panics if cloned while a permit exists. the `Clone` implementation must exist so that
/// `ReservedPermit` can be added to a request via an `Extension`, which requires `Clone`. However,
/// Axum/Tower do not clone the request between middleware and the handler, so this is a safe usage.  
pub struct ReservedPermit<T>(Option<mpsc::OwnedPermit<T>>);

impl<T: Send + 'static> ReservedPermit<T> {
    pub fn new(permit: mpsc::OwnedPermit<T>) -> Self {
        Self(Some(permit))
    }
    /// # Panics
    /// if called more than once
    pub fn send(&mut self, item: T) {
        self.0
            .take()
            .expect("should only call `send` once")
            .send(item);
    }
}

impl<T> Clone for ReservedPermit<T> {
    /// # Panics
    /// if a permit exists
    fn clone(&self) -> Self {
        assert!(self.0.is_none());
        Self(None)
    }
}

/// Middleware that first reserves a permit on the channel to send messages to the messaging layer.
/// Once reserved, adds the permit to the extension for retrieval from the handler.
pub async fn obtain_permit_mw<B: Send>(
    message_send_map: MessageSendMap,
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, MpcHelperServerError> {
    let mut req_parts = RequestParts::new(req);
    let Path(query_id, _) = Path::from_request(&mut req_parts).await?;

    let sender = message_send_map.get(query_id)?;
    let permit = sender.reserve_owned().await?;
    req_parts
        .extensions_mut()
        .insert(ReservedPermit::new(permit));
    let req = req_parts
        .try_into_request()
        .expect("request body should not have been modified");
    Ok(next.run(req).await)
}

/// extracts the [`MessageChunks`] from the request and forwards it to the Message layer via the
/// `permit`. If we try to extract the `permit` via the `Extension`'s `FromRequest` implementation,
/// it will call `.clone()` on it, which will remove the `OwnedPermit`. Thus, we must access the
/// `permit` via `Request::extensions_mut`, which returns [`Extensions`] without cloning.
pub async fn handler(
    path: Path,
    // TODO: we shouldn't trust the client to tell us their role.
    //       revisit when we have figured out discovery/handshake
    query: Query<RoleQueryParam>,
    _headers: RecordHeaders,
    mut req: Request<Body>,
) -> Result<(), MpcHelperServerError> {
    // prepare data
    let Path(_, step) = path;
    let channel_id = ChannelId {
        role: query.role,
        step,
    };

    let body = hyper::body::to_bytes(req.body_mut()).await?.to_vec();

    // send data
    let permit = req
        .extensions_mut()
        .get_mut::<ReservedPermit<MessageChunks>>()
        .unwrap();

    permit.send((channel_id, body));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        helpers::MESSAGE_PAYLOAD_SIZE_BYTES,
        net::{
            server::MessageSendMap, BindTarget, MpcHelperServer, CONTENT_LENGTH_HEADER_NAME,
            OFFSET_HEADER_NAME,
        },
    };
    use axum::body::Bytes;
    use axum::http::{HeaderValue, Request, StatusCode};
    use futures_util::FutureExt;
    use hyper::header::HeaderName;
    use hyper::service::Service;
    use hyper::{body, Body, Client, Response};
    use std::future::Future;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    const DATA_LEN: usize = 3;

    async fn init_server() -> (u16, mpsc::Receiver<MessageChunks>) {
        let (tx, rx) = mpsc::channel(1);
        let message_send_map = MessageSendMap::filled(tx);
        let server = MpcHelperServer::new(message_send_map);
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let port = addr.port();
        (port, rx)
    }

    fn build_req(
        port: u16,
        query_id: QueryId,
        step: &UniqueStepId,
        role: Role,
        offset: u32,
        body: &'static [u8],
    ) -> Request<Body> {
        assert_eq!(
            body.len() % (MESSAGE_PAYLOAD_SIZE_BYTES as usize),
            0,
            "body len must align with data_size"
        );
        let uri = format!(
            "http://127.0.0.1:{}/query/{}/step/{}?role={}",
            port,
            query_id.as_ref(),
            step.as_ref(),
            role.as_ref(),
        );
        #[allow(clippy::cast_possible_truncation)] // `body.len()` known to be less than u32
        let headers = RecordHeaders {
            content_length: body.len() as u32,
            offset,
        };
        let body = Body::from(Bytes::from_static(body));
        headers
            .add_to(Request::post(uri))
            .body(body)
            .expect("request should be valid")
    }

    async fn send_req(
        port: u16,
        query_id: QueryId,
        step: &UniqueStepId,
        helper_role: Role,
        offset: u32,
        body: &'static [u8],
    ) -> Response<Body> {
        // build req
        let req = build_req(port, query_id, step, helper_role, offset, body);

        let client = Client::default();
        client
            .request(req)
            .await
            .expect("client should be able to communicate with server")
    }

    #[tokio::test]
    async fn collect_req() {
        let (port, mut rx) = init_server().await;

        // prepare req
        let query_id = QueryId;
        let target_helper = Role::H2;
        let step = UniqueStepId::default().narrow("test");
        let offset = 0;
        let body = &[213; (DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES) as usize];

        // try a request 10 times
        for _ in 0..10 {
            let resp = send_req(port, query_id, &step, target_helper, offset, body).await;

            let status = resp.status();
            let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
            let resp_body_str = String::from_utf8_lossy(&resp_body);

            // response comparison
            let channel_id = ChannelId {
                role: target_helper,
                step: step.clone(),
            };

            assert_eq!(status, StatusCode::OK, "{}", resp_body_str);
            let messages = rx.try_recv().expect("should have already received value");
            assert_eq!(messages, (channel_id, body.to_vec()));
        }
    }

    struct OverrideReq {
        query_id: String,
        step: String,
        role: String,
        offset_header: (HeaderName, HeaderValue),
        body: &'static [u8],
    }

    impl OverrideReq {
        fn into_req(self, port: u16) -> Request<Body> {
            let uri = format!(
                "http://127.0.0.1:{}/query/{}/step/{}?role={}",
                port, self.query_id, self.step, self.role
            );
            let mut req = Request::post(uri);
            let req_headers = req.headers_mut().unwrap();
            req_headers.insert(CONTENT_LENGTH_HEADER_NAME.clone(), self.body.len().into());
            req_headers.insert(self.offset_header.0, self.offset_header.1);

            req.body(self.body.into()).unwrap()
        }
    }

    impl Default for OverrideReq {
        fn default() -> Self {
            Self {
                query_id: QueryId.as_ref().to_owned(),
                step: UniqueStepId::default().narrow("test").as_ref().to_owned(),
                role: Role::H2.as_ref().to_owned(),
                offset_header: (OFFSET_HEADER_NAME.clone(), 0.into()),
                body: &[34; (DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES) as usize],
            }
        }
    }

    async fn resp_eq(req: OverrideReq, expected_status: StatusCode) {
        let (port, _rx) = init_server().await;
        let resp = Client::default()
            .request(req.into_req(port))
            .await
            .expect("request should complete successfully");
        assert_eq!(resp.status(), expected_status);
    }

    #[tokio::test]
    async fn malformed_query_id_fails() {
        let req = OverrideReq {
            query_id: "not-a-query-id".into(),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_role_fails() {
        let req = OverrideReq {
            role: "h4".into(),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_offset_header_name_fails() {
        let req = OverrideReq {
            offset_header: (HeaderName::from_static("ofset"), 0.into()),
            ..Default::default()
        };
        resp_eq(req, StatusCode::UNPROCESSABLE_ENTITY).await;
    }

    #[tokio::test]
    async fn malformed_offset_header_value_fails() {
        let req = OverrideReq {
            offset_header: (OFFSET_HEADER_NAME.clone(), HeaderValue::from(-1)),
            ..Default::default()
        };
        resp_eq(req, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn wrong_body_size_is_rejected() {
        let req = OverrideReq {
            body: &[0; MESSAGE_PAYLOAD_SIZE_BYTES + 1],
            ..Default::default()
        };
        resp_eq(req, StatusCode::BAD_REQUEST).await;
    }

    #[tokio::test]
    async fn malformed_body_fails() {
        let req = OverrideReq {
            body: &[0, 7],
            ..Default::default()
        };
        resp_eq(req, StatusCode::BAD_REQUEST).await;
    }

    fn poll<F, T>(f: &mut F) -> Poll<T>
    where
        F: Future<Output = T> + Unpin,
    {
        f.poll_unpin(&mut Context::from_waker(futures::task::noop_waker_ref()))
    }

    #[tokio::test]
    async fn backpressure_applied() {
        const QUEUE_DEPTH: usize = 8;
        let (tx, mut rx) = mpsc::channel(QUEUE_DEPTH);
        let message_send_map = MessageSendMap::filled(tx);
        let server = MpcHelperServer::new(message_send_map);
        let mut r = server.router();

        // prepare req
        let query_id = QueryId;
        let step = UniqueStepId::default().narrow("test");
        let target_helper = Role::H2;
        let offset = 0;
        let body = &[0; (DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES) as usize];

        let new_req = || build_req(0, query_id, &step, target_helper, offset, body);

        // fill channel
        for _ in 0..QUEUE_DEPTH {
            let resp = r.ready().await.unwrap().call(new_req()).await.unwrap();
            assert_eq!(
                resp.status(),
                StatusCode::OK,
                "body: {}",
                String::from_utf8_lossy(&body::to_bytes(resp.into_body()).await.unwrap())
            );
        }

        // channel should now be full
        let mut resp_when_full = r.ready().await.unwrap().call(new_req());
        assert!(
            poll(&mut resp_when_full).is_pending(),
            "expected future to be pending"
        );

        // take 1 message from channel
        rx.recv().await;

        // channel should now have capacity
        assert!(poll(&mut resp_when_full).is_ready());

        // take 3 messages from channel
        for _ in 0..3 {
            rx.recv().await;
        }

        // channel should now have capacity for 3 more reqs
        for _ in 0..3 {
            let mut next_req = r.ready().await.unwrap().call(new_req());
            assert!(poll(&mut next_req).is_ready());
        }

        // channel should have no more capacity
        let mut resp_when_full = r.ready().await.unwrap().call(new_req());
        assert!(poll(&mut resp_when_full).is_pending());
    }
}
