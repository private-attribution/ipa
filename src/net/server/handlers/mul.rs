use crate::helpers::fabric::{ChannelId, MessageChunks, MessageEnvelope};
use crate::helpers::Identity;
use crate::net::server::MpcServerError;
use crate::net::RecordHeaders;
use crate::protocol::{QueryId, RecordId, UniqueStepId};
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
    type Rejection = MpcServerError;

    async fn from_request(req: &mut RequestParts<B>) -> Result<Self, Self::Rejection> {
        let extract::Path((query_id, step)) =
            extract::Path::<(QueryId, UniqueStepId)>::from_request(req).await?;
        Ok(Path(query_id, step))
    }
}

#[cfg_attr(feature = "enable-serde", derive(serde::Deserialize))]
pub struct IdentityQuery {
    identity: Identity,
}

/// After an [`OwnedPermit`] has been reserved, it can be used once to send an item on the channel.
/// Panics if cloned while a permit exists.
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

pub async fn obtain_permit_mw<T: Send + 'static, B>(
    sender: mpsc::Sender<T>,
    mut req: Request<B>,
    next: Next<B>,
) -> Result<Response, MpcServerError> {
    let permit = sender.reserve_owned().await?;
    req.extensions_mut().insert(ReservedPermit::new(permit));
    Ok(next.run(req).await)
}

/// extracts the [`MessageChunks`] from the request and forwards it to the Message layer via the
/// `permit`. If we try to extract the `permit` via the `Extension`'s `FromRequest` implementation,
/// it will call `.clone()` on it, which will remove the `OwnedPermit`. Thus, we must access the
/// `permit` via `Request::extensions_mut`, which returns [`Extensions`] without cloning.
#[allow(clippy::unused_async)] // handler is expected to be async
#[allow(clippy::cast_possible_truncation)] // length of envelopes array known to be less u32
pub async fn handler(
    Path(_query_id, step): Path,
    // TODO: we shouldn't trust the client to tell us their identity.
    //       revisit when we have figured out discovery/handshake
    Query(IdentityQuery { identity }): Query<IdentityQuery>,
    headers: RecordHeaders,
    mut req: Request<Body>,
) -> Result<(), MpcServerError> {
    // prepare data
    let channel_id = ChannelId { identity, step };

    let body = hyper::body::to_bytes(req.body_mut()).await?;
    headers.matches_body(body.len())?;
    let envelopes = body
        .as_ref()
        .chunks(headers.data_size as usize)
        .enumerate()
        .map(|(record_id, chunk)| MessageEnvelope {
            record_id: RecordId::from(headers.offset + record_id as u32),
            payload: chunk.to_vec().into_boxed_slice(),
        })
        .collect::<Vec<_>>();

    // send data
    let permit = req
        .extensions_mut()
        .get_mut::<ReservedPermit<MessageChunks>>()
        .unwrap();

    permit.send((channel_id, envelopes));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::{BindTarget, MpcServer, DATA_SIZE_HEADER_NAME, OFFSET_HEADER_NAME};
    use axum::body::Bytes;
    use axum::http::{HeaderValue, Request, StatusCode};
    use hyper::header::HeaderName;
    use hyper::service::Service;
    use hyper::{body, Body, Client, Response};
    use std::collections::HashMap;
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use tokio::sync::mpsc;
    use tower::ServiceExt;

    const DATA_SIZE: u32 = 4;
    const DATA_LEN: u32 = 3;

    async fn init_server() -> (u16, mpsc::Receiver<MessageChunks>) {
        let (tx, rx) = mpsc::channel(1);
        let server = MpcServer::new(tx);
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let port = addr.port();
        (port, rx)
    }

    fn build_req(
        port: u16,
        query_id: QueryId,
        step: UniqueStepId,
        identity: Identity,
        offset: u32,
        body: &'static [u8],
    ) -> Request<Body> {
        assert_eq!(
            body.len() % (DATA_SIZE as usize),
            0,
            "body len must align with data_size"
        );
        let uri = format!(
            "http://127.0.0.1:{}/mul/query-id/{}/step/{}?identity={}",
            port,
            String::from(query_id),
            String::from(step),
            String::from(identity),
        );
        let headers = RecordHeaders {
            offset,
            data_size: DATA_SIZE as u32,
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
        step: UniqueStepId,
        identity: Identity,
        offset: u32,
        body: &'static [u8],
    ) -> Response<Body> {
        // build req
        let req = build_req(port, query_id, step, identity, offset, body);

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
        let target_helper = Identity::H2;
        let step = UniqueStepId::default().narrow("test");
        let offset = 0;
        let body = &[0; (DATA_LEN * DATA_SIZE) as usize];

        // try a request 10 times
        for _ in 0..10 {
            let resp = send_req(port, query_id, step.clone(), target_helper, offset, body).await;

            let status = resp.status();
            let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
            let resp_body_str = String::from_utf8_lossy(&resp_body);

            // response comparison
            let channel_id = ChannelId {
                identity: target_helper,
                step: step.clone(),
            };
            let env = [0; DATA_SIZE as usize].to_vec().into_boxed_slice();
            let envs = (0..DATA_LEN)
                .map(|i| MessageEnvelope {
                    record_id: i.into(),
                    payload: env.clone(),
                })
                .collect::<Vec<_>>();

            assert_eq!(status, StatusCode::OK, "{}", resp_body_str);
            let messages = rx.try_recv().expect("should have already received value");
            assert_eq!(messages, (channel_id, envs));
        }
    }

    #[allow(clippy::mutable_key_type)] // `HeaderName` is known good key
    fn build_malformed_req<Q: Into<String>, S: Into<String>, I: Into<String>, B: Into<Body>>(
        port: u16,
        query_id: Q,
        step: S,
        identity: I,
        headers: HashMap<HeaderName, HeaderValue>,
        body: B,
    ) -> Request<Body> {
        let uri = format!(
            "http://127.0.0.1:{}/mul/query-id/{}/step/{}?identity={}",
            port,
            query_id.into(),
            step.into(),
            identity.into(),
        );

        let mut req = Request::post(uri);
        let req_headers = req.headers_mut().unwrap();
        for (key, value) in headers {
            req_headers.insert(key, value);
        }
        req.body(body.into()).unwrap()
    }

    async fn expect_res(req: Request<Body>, expected_status: StatusCode) {
        let resp = Client::default()
            .request(req)
            .await
            .expect("request should complete successfully");
        assert_eq!(resp.status(), expected_status);
    }

    #[tokio::test]
    #[allow(clippy::mutable_key_type)] // [`HeaderName`] is known good key
    #[allow(clippy::too_many_lines)] // testing all permutations of request
    async fn malformed_req_fails() {
        const MALFORMED_DATA_SIZE: usize = 7;
        let (port, rx) = init_server().await;
        tokio::spawn(async move {
            let mut rx = Box::pin(rx);
            while let Some(next) = rx.recv().await {
                println!("received value on receive: {:?}", next.0);
            }
        });

        // well-formed request
        let valid_query_id = QueryId;
        let valid_target_helper = Identity::H2;
        let valid_step = UniqueStepId::default().narrow("test");
        let valid_offset = 0;
        let valid_body = Bytes::from_static(&[0; (DATA_LEN * DATA_SIZE) as usize]);
        let valid_headers = HashMap::from([
            (OFFSET_HEADER_NAME.clone(), valid_offset.into()),
            (DATA_SIZE_HEADER_NAME.clone(), DATA_SIZE.into()),
        ]);

        // malformed request
        let malformed_query_id = "not-a-query-id";
        let malformed_target_helper = "h4";
        let malformed_offset = -1;
        #[allow(clippy::cast_possible_truncation)] // value == 7
        let malformed_body = Bytes::from_static(&[0, MALFORMED_DATA_SIZE as u8]);
        let malformed_offset_name_headers = HashMap::from([
            (HeaderName::from_static("ofset"), valid_offset.into()),
            (DATA_SIZE_HEADER_NAME.clone(), DATA_SIZE.into()),
        ]);
        let malformed_offset_value_headers = HashMap::from([
            (OFFSET_HEADER_NAME.clone(), malformed_offset.into()),
            (DATA_SIZE_HEADER_NAME.clone(), DATA_SIZE.into()),
        ]);
        let malformed_data_size_name_headers = HashMap::from([
            (OFFSET_HEADER_NAME.clone(), valid_offset.into()),
            (HeaderName::from_static("datasize"), DATA_SIZE.into()),
        ]);
        let malformed_data_size_value_headers = HashMap::from([
            (OFFSET_HEADER_NAME.clone(), valid_offset.into()),
            (DATA_SIZE_HEADER_NAME.clone(), MALFORMED_DATA_SIZE.into()),
        ]);

        // malformed query_id
        let req = build_malformed_req(
            port,
            malformed_query_id,
            valid_step.clone(),
            valid_target_helper,
            valid_headers.clone(),
            valid_body.clone(),
        );
        expect_res(req, StatusCode::UNPROCESSABLE_ENTITY).await;

        // malformed identity
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            malformed_target_helper,
            valid_headers.clone(),
            valid_body.clone(),
        );
        expect_res(req, StatusCode::UNPROCESSABLE_ENTITY).await;

        // malformed offset header name
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            valid_target_helper,
            malformed_offset_name_headers,
            valid_body.clone(),
        );
        expect_res(req, StatusCode::UNPROCESSABLE_ENTITY).await;

        // malformed offset header value
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            valid_target_helper,
            malformed_offset_value_headers,
            valid_body.clone(),
        );
        expect_res(req, StatusCode::BAD_REQUEST).await;

        // malformed data-size header name
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            valid_target_helper,
            malformed_data_size_name_headers,
            valid_body.clone(),
        );
        expect_res(req, StatusCode::UNPROCESSABLE_ENTITY).await;

        // malformed data-size header value
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            valid_target_helper,
            malformed_data_size_value_headers,
            valid_body.clone(),
        );
        expect_res(req, StatusCode::BAD_REQUEST).await;

        // malformed body
        let req = build_malformed_req(
            port,
            valid_query_id,
            valid_step.clone(),
            valid_target_helper,
            valid_headers.clone(),
            malformed_body,
        );
        expect_res(req, StatusCode::BAD_REQUEST).await;
    }

    fn poll<F, T>(f: &mut F) -> Poll<T>
    where
        F: Future<Output = T> + Unpin,
    {
        Pin::new(f).poll(&mut Context::from_waker(futures::task::noop_waker_ref()))
    }

    #[tokio::test]
    async fn backpressure_applied() {
        const QUEUE_DEPTH: usize = 8;
        let (tx, mut rx) = mpsc::channel(QUEUE_DEPTH);
        let server = MpcServer::new(tx);
        let mut r = server.router();

        // prepare req
        let query_id = QueryId;
        let step = UniqueStepId::default().narrow("test");
        let target_helper = Identity::H2;
        let offset = 0;
        let body = &[0; (DATA_LEN * DATA_SIZE) as usize];

        let new_req = || build_req(0, query_id, step.clone(), target_helper, offset, body);

        // fill channel
        for _ in 0..QUEUE_DEPTH {
            r.ready().await.unwrap().call(new_req()).await.unwrap();
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
