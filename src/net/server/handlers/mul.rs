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
    RecordHeaders { offset, data_size }: RecordHeaders,
    mut req: Request<Body>,
) -> Result<(), MpcServerError> {
    // prepare data
    let channel_id = ChannelId { identity, step };

    let body = hyper::body::to_bytes(req.body_mut()).await?;
    let envelopes = body
        .as_ref()
        .chunks(data_size as usize)
        .enumerate()
        .map(|(record_id, chunk)| MessageEnvelope {
            record_id: RecordId::from(offset + record_id as u32),
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
    use crate::net::{BindTarget, MpcServer};
    use axum::body::Bytes;
    use axum::http::{Request, StatusCode};
    use hyper::{body, Body, Client};
    use tokio::sync::mpsc;

    const DATA_SIZE: u32 = 4;
    const DATA_LEN: u32 = 3;

    async fn send_req(
        rx: &mut mpsc::Receiver<MessageChunks>,
        port: u16,
        query_id: QueryId,
        step: UniqueStepId,
        identity: Identity,
        offset: u32,
        body: &'static [u8],
    ) {
        // build req
        assert_eq!(
            body.len() % (DATA_SIZE as usize),
            0,
            "body len must align with data_size"
        );
        let uri = format!(
            "http://127.0.0.1:{}/mul/query-id/{}/step/{}?identity={}",
            port,
            query_id,
            String::from(step.clone()),
            String::from(identity),
        );
        let headers = RecordHeaders {
            offset,
            data_size: DATA_SIZE as u32,
        };
        let body = Body::from(Bytes::from_static(body));
        let req = headers
            .add_to(Request::post(uri))
            .body(body)
            .expect("request should be valid");

        let client = Client::default();
        let resp = client
            .request(req)
            .await
            .expect("client should be able to communicate with server");
        let status = resp.status();
        let resp_body = body::to_bytes(resp.into_body()).await.unwrap();
        let resp_body_str = String::from_utf8_lossy(&resp_body);

        // response comparison
        let channel_id = ChannelId { identity, step };
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

    #[tokio::test]
    async fn collect_req() {
        // initialize server
        let (tx, mut rx) = mpsc::channel(1);
        let server = MpcServer::new(tx);
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;
        let port = addr.port();

        // prepare req
        let query_id = QueryId;
        let target_helper = Identity::H2;
        let step = UniqueStepId::default().narrow("test");
        let offset = 0;
        let body = &[0; (DATA_LEN * DATA_SIZE) as usize];

        // try a request 10 times
        for _ in 0..10 {
            send_req(
                &mut rx,
                port,
                query_id,
                step.clone(),
                target_helper,
                offset,
                body,
            )
            .await;
        }
    }
}
