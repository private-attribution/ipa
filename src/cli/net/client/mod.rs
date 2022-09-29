use super::Command;
use crate::cli::net::{DATA_SIZE_HEADER_NAME, OFFSET_HEADER_NAME};
use crate::helpers::mesh::Message;
use crate::protocol::{QueryId, Step};
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

    async fn mul<S: Step, M: Message>(
        &self,
        query_id: QueryId,
        step: S,
        offset: usize,
        data_size: usize,
        messages: Bytes,
    ) -> Result<(), MpcClientError> {
        let uri = self.build_uri(format!(
            "/mul/query-id/{}/step/{}",
            query_id.to_string(),
            step.to_string()
        ))?;
        let body = Body::from(messages);
        let req = Request::post(uri)
            .header(OFFSET_HEADER_NAME, offset)
            .header(DATA_SIZE_HEADER_NAME, data_size)
            .body(body)?;
        let response = self.client.request(req).await?;
        let resp_status = response.status();
        resp_status
            .is_success()
            .then_some(())
            .ok_or(MpcClientError::FailedRequest(resp_status))
    }
}
