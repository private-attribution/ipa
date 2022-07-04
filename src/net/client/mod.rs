use async_trait::async_trait;
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
}

#[async_trait]
pub trait MpcHandle {
    async fn execute(&self, command: Command) -> Result<Vec<u8>, MpcClientError>;
}

pub struct MpcHttpConnection {
    client: Client<HttpsConnector<HttpConnector>>,
    addr: Uri,
}

#[async_trait]
impl MpcHandle for MpcHttpConnection {
    async fn execute(&self, command: Command) -> Result<Vec<u8>, MpcClientError> {
        match command {
            Command::Echo(s) => self.echo(&s).await,
        }
    }
}

impl MpcHttpConnection {
    #[must_use]
    pub fn new(addr: &str) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, Body>(https);

        Self {
            client,
            addr: addr.parse().expect("Cannot parse the URI"),
        }
    }

    async fn echo(&self, s: &str) -> Result<Vec<u8>, MpcClientError> {
        let uri: Uri = format!("{}echo?foo={}", self.addr, s)
            .parse()
            .expect("Failed to build an URI for \"echo\" command");

        let response = self.client.get(uri).await?;
        let result = hyper::body::to_bytes(response.into_body()).await?;

        Ok(result.to_vec())
    }
}
