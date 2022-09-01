use crate::error::BoxError;
use crate::field::Field;
use crate::helpers::Identity;
use crate::protocol::{QueryId, Step};
use crate::replicated_secret_sharing::ReplicatedSecretSharing;
use async_trait::async_trait;
use axum::http::uri::{self, InvalidUri, PathAndQuery};
use axum::http::Request;
use futures::{Stream, StreamExt};
use hyper::client::HttpConnector;
use hyper::{Body, Client, Uri};
use hyper_tls::HttpsConnector;
use thiserror::Error as ThisError;

use super::Command;

#[derive(ThisError, Debug)]
pub enum MpcClientError {
    #[error("invalid host address")]
    InvalidHostAddress(String),

    #[error("network connection error")]
    NetworkConnection(#[from] hyper::Error),

    #[error("failed request: {0}")]
    FailedRequest(hyper::StatusCode),

    #[error(transparent)]
    AxumError(#[from] axum::http::Error),
}

#[async_trait]
pub trait MpcHandle<F, S> {
    async fn execute(&self, command: Command<F, S>) -> Result<Vec<u8>, MpcClientError>;
}

pub struct MpcHttpConnection {
    identity: Identity,
    client: Client<HttpsConnector<HttpConnector>>,
    addr: Uri,
    addr_parts: uri::Parts,
}

impl Clone for MpcHttpConnection {
    fn clone(&self) -> Self {
        Self {
            identity: self.identity,
            client: self.client.clone(),
            addr: self.addr.clone(),
            // must implement clone due to this line
            addr_parts: self.addr.clone().into_parts(),
        }
    }
}

#[async_trait]
impl<F: Field, S: Step> MpcHandle<F, S> for MpcHttpConnection {
    async fn execute(&self, command: Command<F, S>) -> Result<Vec<u8>, MpcClientError> {
        match command {
            Command::Echo(s) => self.echo(&s).await,
            Command::Mul(_, _, _) => unimplemented!("use mul function directly"),
        }
    }
}

impl MpcHttpConnection {
    #[must_use]
    pub fn new(identity: Identity, addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https);

        let addr_parts = addr.clone().into_parts();
        Self {
            identity,
            client,
            addr,
            addr_parts,
        }
    }

    pub fn with_str_addr(identity: Identity, addr: &str) -> Result<Self, InvalidUri> {
        addr.parse().map(|addr| Self::new(identity, addr))
    }

    fn build_uri<T>(&self, p_and_q: T) -> Result<Uri, MpcClientError>
    where
        PathAndQuery: TryFrom<T>,
        <PathAndQuery as TryFrom<T>>::Error: Into<axum::http::Error>,
    {
        Ok(uri::Builder::new()
            .scheme(self.addr_parts.scheme.unwrap().clone())
            .authority(self.addr_parts.authority.unwrap().clone())
            .path_and_query(p_and_q)
            .build()?)
    }

    async fn echo(&self, s: &str) -> Result<Vec<u8>, MpcClientError> {
        let uri = self.build_uri(format!("/echo?foo={}", s))?;

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;

        Ok(result.to_vec())
    }

    /// TODO: `execute` function doesn't seem like the best abstraction due to all the generics here
    pub async fn mul<F, St, S>(
        &self,
        shares: St,
        query_id: QueryId,
        step: S,
    ) -> Result<(), MpcClientError>
    where
        F: Field,
        St: Stream<Item = ReplicatedSecretSharing<F>> + Send + 'static,
        S: Step,
    {
        let uri = self.build_uri(format!(
            "/mul/query_id/{}/step/{}?identity={}",
            query_id,
            step.to_path(),
            self.identity,
        ))?;

        let req = Request::post(uri).body(Body::wrap_stream(
            shares.map(Result::<ReplicatedSecretSharing<F>, BoxError>::Ok),
        ))?;
        let response = self.client.request(req).await?;
        let resp_status = response.status();
        resp_status
            .is_success()
            .then_some(())
            .ok_or(MpcClientError::FailedRequest(resp_status))
    }
}
