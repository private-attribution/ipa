use super::Command;
use crate::helpers::Identity;
use crate::net::RecordHeaders;
use crate::protocol::{QueryId, UniqueStepId};
use async_trait::async_trait;
use axum::body::Bytes;
use axum::http::uri::{self, PathAndQuery};
use axum::http::Request;
use hyper::client::HttpConnector;
use hyper::{Body, Client, Uri};
use hyper_tls::HttpsConnector;
use thiserror::Error as ThisError;

#[allow(dead_code)]
#[derive(ThisError, Debug)]
pub enum MpcClientError {
    #[error("invalid host address")]
    InvalidHostAddress(#[from] uri::InvalidUri),

    #[error("network connection error")]
    NetworkConnection(#[from] hyper::Error),

    #[error("failed request: {0}")]
    FailedRequest(hyper::StatusCode),

    #[error(transparent)]
    AxumError(#[from] axum::http::Error),
}

#[async_trait]
pub trait MpcHandle {
    async fn execute(&self, command: Command) -> Result<Vec<u8>, MpcClientError>;
}

pub struct MpcHttpConnection {
    client: Client<HttpsConnector<HttpConnector>>,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

#[async_trait]
impl MpcHandle for MpcHttpConnection {
    async fn execute(&self, command: Command) -> Result<Vec<u8>, MpcClientError> {
        match command {
            Command::Echo(s) => self.echo(&s).await,
        }
    }
}

#[allow(dead_code)]
impl MpcHttpConnection {
    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https);

        let parts = addr.into_parts();

        Self {
            client,
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    /// same as new, but first parses the addr from a [&str]
    /// # Errors
    /// if addr is an invalid [Uri], this will fail
    pub fn with_str_addr(addr: &str) -> Result<Self, MpcClientError> {
        Ok(Self::new(addr.parse()?))
    }

    fn build_uri<T>(&self, p_and_q: T) -> Result<Uri, MpcClientError>
    where
        PathAndQuery: TryFrom<T>,
        <PathAndQuery as TryFrom<T>>::Error: Into<axum::http::Error>,
    {
        Ok(uri::Builder::new()
            .scheme(self.scheme.clone())
            .authority(self.authority.clone())
            .path_and_query(p_and_q)
            .build()?)
    }

    async fn echo(&self, s: &str) -> Result<Vec<u8>, MpcClientError> {
        let uri = self.build_uri(format!("/echo?foo={}", s))?;

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;

        Ok(result.to_vec())
    }

    async fn mul(&self, args: HttpMulArgs<'_>) -> Result<(), MpcClientError> {
        let uri = self.build_uri(format!(
            "/mul/query-id/{}/step/{}?identity={}",
            args.query_id.as_ref(),
            args.step.as_ref(),
            args.identity.as_ref(),
        ))?;
        #[allow(clippy::cast_possible_truncation)] // `messages.len` is known to be smaller than u32
        let headers = RecordHeaders {
            content_length: args.messages.len() as u32,
            offset: args.offset,
            data_size: args.data_size,
        };
        let req = headers
            .add_to(Request::post(uri))
            .body(Body::from(args.messages))?;
        let response = self.client.request(req).await?;
        let resp_status = response.status();
        resp_status
            .is_success()
            .then_some(())
            .ok_or(MpcClientError::FailedRequest(resp_status))
    }
}

pub struct HttpMulArgs<'a> {
    pub query_id: &'a QueryId,
    pub step: &'a UniqueStepId,
    pub identity: Identity,
    pub offset: u32,
    pub data_size: u32,
    pub messages: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::fabric::{ChannelId, MessageChunks, MessageEnvelope};
    use crate::net::{BindTarget, MpcServer};
    use hyper_tls::native_tls::TlsConnector;
    use tokio::sync::mpsc;

    async fn mul_req(client: MpcHttpConnection, mut rx: mpsc::Receiver<MessageChunks>) {
        const DATA_SIZE: u32 = 4;
        const DATA_LEN: u32 = 3;
        let query_id = QueryId;
        let step = UniqueStepId::default().narrow("mul_test");
        let identity = Identity::H1;
        let offset = 0;
        let messages = &[0; (DATA_SIZE * DATA_LEN) as usize];

        let res = client
            .mul(HttpMulArgs {
                query_id: &query_id,
                step: &step,
                identity,
                offset,
                data_size: DATA_SIZE,
                messages: Bytes::from_static(messages),
            })
            .await;
        assert!(res.is_ok(), "{}", res.unwrap_err());

        let channel_id = ChannelId { identity, step };
        let env = [0; DATA_SIZE as usize].to_vec().into_boxed_slice();
        let envs = (0..DATA_LEN)
            .map(|i| MessageEnvelope {
                record_id: i.into(),
                payload: env.clone(),
            })
            .collect::<Vec<_>>();
        let server_recvd = rx.try_recv().unwrap(); // should already have been received
        assert_eq!(server_recvd, (channel_id, envs));
    }

    #[tokio::test]
    async fn mul_req_http() {
        let (tx, rx) = mpsc::channel(1);
        let server = MpcServer::new(tx);
        // setup server
        let (addr, _) = server
            .bind(BindTarget::Http("127.0.0.1:0".parse().unwrap()))
            .await;

        // setup client
        let client =
            MpcHttpConnection::with_str_addr(&format!("http://localhost:{}", addr.port())).unwrap();

        // test
        mul_req(client, rx).await;
    }

    #[tokio::test]
    async fn mul_req_https() {
        // setup server
        let (tx, rx) = mpsc::channel(1);
        let server = MpcServer::new(tx);
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (addr, _) = server
            .bind(BindTarget::Https("127.0.0.1:0".parse().unwrap(), config))
            .await;

        // setup client
        // requires custom client to use self signed certs
        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let hyper_client = hyper::Client::builder().build(https);
        let client = MpcHttpConnection {
            client: hyper_client,
            scheme: uri::Scheme::HTTPS,
            authority: uri::Authority::try_from(format!("localhost:{}", addr.port())).unwrap(),
        };

        // test
        mul_req(client, rx).await;
    }
}
