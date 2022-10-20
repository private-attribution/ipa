use super::Command;
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

    async fn mul(
        &self,
        query_id: QueryId,
        step: UniqueStepId,
        offset: u32,
        data_size: u32,
        messages: Bytes,
    ) -> Result<(), MpcClientError> {
        let uri = self.build_uri(format!(
            "/mul/query-id/{}/step/{}",
            query_id,
            String::from(step)
        ))?;
        let body = Body::from(messages);
        let headers = RecordHeaders { offset, data_size };
        let req = headers.add_to(Request::post(uri)).body(body)?;
        let response = self.client.request(req).await?;
        let resp_status = response.status();
        resp_status
            .is_success()
            .then_some(())
            .ok_or(MpcClientError::FailedRequest(resp_status))
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::net::{bind_mpc_helper_server, BindTarget, BufferedMessages};
//     use crate::protocol::IPAProtocolStep;
//     use hyper_tls::native_tls::TlsConnector;
//     use std::collections::HashMap;
//     use std::sync::{Arc, Mutex};
//     use tokio::sync::mpsc;
//
//     async fn mul_req(client: MpcHttpConnection, gateway_map: GatewayMap<IPAProtocolStep>) {
//         const DATA_SIZE: u32 = 4;
//         let query_id = QueryId;
//         let step = IPAProtocolStep::ConvertShares;
//         let offset = 0;
//         let messages = &[0; DATA_SIZE as usize * 3];
//
//         // setup map to contain sender
//         let (tx, mut rx) = mpsc::channel(1);
//         gateway_map.lock().unwrap().insert((query_id, step), tx);
//
//         let res = client
//             .mul(
//                 query_id,
//                 step,
//                 offset,
//                 DATA_SIZE as u32,
//                 Bytes::from_static(messages),
//             )
//             .await;
//         assert!(res.is_ok(), "{}", res.unwrap_err());
//         let server_recvd = rx.try_recv().unwrap(); // should already have been received
//         assert_eq!(
//             server_recvd,
//             BufferedMessages {
//                 query_id,
//                 step,
//                 offset,
//                 data_size: DATA_SIZE as u32,
//                 body: Bytes::from_static(messages)
//             }
//         );
//     }
//
//     #[tokio::test]
//     async fn mul_req_http() {
//         // setup server
//         let m = Arc::new(Mutex::new(HashMap::new()));
//         let (addr, _) = bind_mpc_helper_server::<IPAProtocolStep>(
//             BindTarget::Http("127.0.0.1:0".parse().unwrap()),
//             Arc::clone(&m),
//         )
//         .await;
//
//         // setup client
//         let client =
//             MpcHttpConnection::with_str_addr(&format!("http://localhost:{}", addr.port())).unwrap();
//
//         // test
//         mul_req(client, m).await;
//     }
//
//     #[tokio::test]
//     async fn mul_req_https() {
//         // setup server
//         let m = Arc::new(Mutex::new(HashMap::new()));
//         let config = crate::net::server::tls_config_from_self_signed_cert()
//             .await
//             .unwrap();
//         let (addr, _) = bind_mpc_helper_server(
//             BindTarget::Https("127.0.0.1:0".parse().unwrap(), config),
//             Arc::clone(&m),
//         )
//         .await;
//
//         // setup client
//         // requires custom client to use self signed certs
//         let conn = TlsConnector::builder()
//             .danger_accept_invalid_certs(true)
//             .build()
//             .unwrap();
//         let mut http = HttpConnector::new();
//         http.enforce_http(false);
//         let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
//         let hyper_client = hyper::Client::builder().build(https);
//         let client = MpcHttpConnection {
//             client: hyper_client,
//             scheme: uri::Scheme::HTTPS,
//             authority: uri::Authority::try_from(format!("localhost:{}", addr.port())).unwrap(),
//         };
//
//         // test
//         mul_req(client, m).await;
//     }
// }
