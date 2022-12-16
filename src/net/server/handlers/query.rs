use crate::helpers::network::{ChannelId, MessageChunks};
use crate::helpers::Role;
use crate::net::server::{LastSeenMessages, MessageSendMap, MpcHelperServerError};
use crate::net::RecordHeaders;
use crate::protocol::{QueryId, Step};
use axum::extract::{Path, Query, RequestParts};
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use axum::Extension;
use hyper::Body;
use tokio::sync::mpsc;

/// Used in the axum handler to extract the peer role from the query params of the request
#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
struct RoleQueryParam {
    role: Role,
}

/// After an [`mpsc::OwnedPermit`] has been reserved, it can be used once to send an item on the channel.
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
/// # Panics
/// if messages arrive out of order
pub async fn obtain_permit_mw<B: Send>(
    req: Request<B>,
    next: Next<B>,
) -> Result<Response, MpcHelperServerError> {
    // extract everything from the request; middleware cannot have these in the function signature
    let mut req_parts = RequestParts::new(req);
    let Path::<(QueryId, Step)>((query_id, step)) = req_parts.extract().await?;
    // TODO: we shouldn't trust the client to tell us their role.
    //       revisit when we have figured out discovery/handshake
    let Query(RoleQueryParam { role }) = req_parts.extract().await?;
    let record_headers = req_parts.extract::<RecordHeaders>().await?;
    let Extension::<LastSeenMessages>(last_seen_messages) = req_parts.extract().await?;
    let Extension::<MessageSendMap>(message_send_map) = req_parts.extract().await?;

    // PANIC if messages arrive out of order; pretty print the error
    // TODO (ts): remove this when streaming solution is complete
    let channel_id = ChannelId::new(role, step);
    last_seen_messages.ensure_ordering(&channel_id, record_headers.offset);

    // get sender to correct network
    let sender = message_send_map.get(query_id)?;
    let permit = sender.reserve_owned().await?;

    // insert different parts as extensions so that handler doesn't need to extract again
    req_parts.extensions_mut().insert(channel_id);
    req_parts
        .extensions_mut()
        .insert(ReservedPermit::new(permit));

    let req = req_parts.try_into_request().unwrap();
    Ok(next.run(req).await)
}

/// extracts the [`MessageChunks`] from the request and forwards it to the Message layer via the
/// `permit`. If we try to extract the [`ReservedPermit`] via the `Extensions`'s `FromRequest` implementation,
/// it will call `.clone()` on it, which will remove the [`mpsc::OwnedPermit`]. Thus, we must access the
/// `[ReservedPermit]` via [`Request::extensions_mut`], which returns `Extensions` without cloning.
pub async fn handler(mut req: Request<Body>) -> Result<(), MpcHelperServerError> {
    // prepare data
    let channel_id = req.extensions().get::<ChannelId>().unwrap().clone();
    let body = hyper::body::to_bytes(req.body_mut()).await?.to_vec();

    tracing::debug!("received {} bytes from {channel_id:?}", body.len());

    // send data
    let permit = req
        .extensions_mut()
        .get_mut::<ReservedPermit<MessageChunks>>()
        .unwrap();

    permit.send((channel_id, body));
    Ok(())
}

#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    use crate::{
        helpers::{http::HttpNetwork, network::Network, MESSAGE_PAYLOAD_SIZE_BYTES},
        net::{
            server::MessageSendMap, BindTarget, MpcHelperServer, CONTENT_LENGTH_HEADER_NAME,
            OFFSET_HEADER_NAME,
        },
    };
    use axum::body::Bytes;
    use axum::http::{HeaderValue, Request, StatusCode};
    use futures::{Stream, StreamExt};
    use futures_util::FutureExt;
    use hyper::header::HeaderName;
    use hyper::service::Service;
    use hyper::{body, Body, Client, Response};
    use std::future::Future;
    use std::task::{Context, Poll};
    use tower::ServiceExt;

    const DATA_LEN: usize = 3;

    async fn init_server() -> (u16, impl Stream<Item = MessageChunks>) {
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let rx_stream = network.recv_stream();
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let port = addr.port();
        (port, rx_stream)
    }

    fn build_req(
        port: u16,
        query_id: QueryId,
        step: &Step,
        role: Role,
        offset: u32,
        body: &'static [u8],
    ) -> Request<Body> {
        assert_eq!(
            body.len() % MESSAGE_PAYLOAD_SIZE_BYTES,
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
        let headers = RecordHeaders {
            content_length: u32::try_from(body.len()).unwrap(),
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
        step: &Step,
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
        let (port, mut rx_stream) = init_server().await;

        // prepare req
        let query_id = QueryId;
        let target_helper = Role::H2;
        let step = Step::default().narrow("test");
        let body = &[213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];

        // try a request 10 times
        for offset in 0..10 {
            let resp = send_req(port, query_id, &step, target_helper, offset, body).await;

            let status = resp.status();
            let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
            let resp_body_str = String::from_utf8_lossy(&resp_body);

            // response comparison
            let channel_id = ChannelId {
                role: target_helper,
                step: step.clone(),
            };

            assert_eq!(status, StatusCode::OK, "{resp_body_str}");
            let messages = rx_stream
                .next()
                .await
                .expect("should have already received value");
            assert_eq!(messages, (channel_id, body.to_vec()));
        }
    }

    #[tokio::test]
    async fn ensure_ordering() {
        let (port, _rx) = init_server().await;

        // prepare req
        let query_id = QueryId;
        let target_helper = Role::H2;
        let step = Step::default().narrow("test");
        let body = &[213; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];

        // offset == 0; this is correct
        let resp = send_req(port, query_id, &step, target_helper, 0, body).await;
        let resp_status = resp.status();
        let body_bytes = body::to_bytes(resp.into_body()).await.unwrap();
        assert!(
            resp_status.is_success(),
            "{}",
            String::from_utf8_lossy(&body_bytes).as_ref()
        );

        // offset == 0; this is invalid
        let req = build_req(port, query_id, &step, target_helper, 0, body);
        let client = Client::default();
        let resp = client.request(req).await;
        let resp_err_msg = format!("{}", resp.unwrap_err());
        assert_eq!(
            resp_err_msg.as_str(),
            "connection closed before message completed"
        );
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
                step: Step::default().narrow("test").as_ref().to_owned(),
                role: Role::H2.as_ref().to_owned(),
                offset_header: (OFFSET_HEADER_NAME.clone(), 0.into()),
                body: &[34; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES],
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
        let network = HttpNetwork::new_without_clients(QueryId, Some(QUEUE_DEPTH));
        let mut rx_stream = network.recv_stream();
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        let mut r = server.router();

        // prepare req
        let query_id = QueryId;
        let step = Step::default().narrow("test");
        let target_helper = Role::H2;
        let mut offset = 0;
        let body = &[0; DATA_LEN * MESSAGE_PAYLOAD_SIZE_BYTES];

        let mut new_req = || {
            let req = build_req(0, query_id, &step, target_helper, offset, body);
            offset += 1;
            req
        };

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
        rx_stream.next().await;

        // channel should now have capacity
        assert!(poll(&mut resp_when_full).is_ready());

        // take 3 messages from channel
        for _ in 0..3 {
            rx_stream.next().await;
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
