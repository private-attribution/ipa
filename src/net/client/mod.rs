mod error;

pub use error::Error;

use crate::{
    helpers::{
        query::{PrepareQuery, QueryConfig, QueryInput},
        transport::ByteArrStream,
        HelperIdentity,
    },
    net::{discovery::peer, http_serde},
    protocol::{QueryId, Step},
};
use axum::{body::StreamBody, http::uri};
use hyper::{body, client::HttpConnector, Body, Client, Response, Uri};
use hyper_tls::HttpsConnector;
use std::collections::HashMap;

/// TODO: we need a client that can be used by any system that is not aware of the internals
///       of the helper network. That means that create query and send inputs API need to be
///       separated from prepare/step data etc.
#[allow(clippy::type_complexity)] // TODO: maybe alias a type for the `dyn Stream`
#[derive(Debug, Clone)]
pub struct MpcHelperClient {
    client: Client<HttpsConnector<HttpConnector>, Body>,
    streaming_client: Client<HttpsConnector<HttpConnector>, StreamBody<ByteArrStream>>,
    scheme: uri::Scheme,
    authority: uri::Authority,
}

impl MpcHelperClient {
    #[must_use]
    #[allow(clippy::missing_panics_doc)]
    pub fn from_conf(peers_conf: &[peer::Config; 3]) -> [MpcHelperClient; 3] {
        peers_conf
            .iter()
            .map(|conf| Self::new(conf.origin.clone()))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap()
    }

    /// addr must have a valid scheme and authority
    /// # Panics
    /// if addr does not have scheme and authority
    #[must_use]
    pub fn new(addr: Uri) -> Self {
        // this works for both http and https
        let https = HttpsConnector::new();
        let client = Client::builder().build(https.clone());
        let streaming_client = Client::builder().build(https);
        let parts = addr.into_parts();
        Self {
            client,
            streaming_client,
            scheme: parts.scheme.unwrap(),
            authority: parts.authority.unwrap(),
        }
    }

    /// same as new, but first parses the addr from a [&str]
    /// # Errors
    /// if addr is an invalid [Uri], this will fail
    pub fn with_str_addr(addr: &str) -> Result<Self, Error> {
        Ok(Self::new(addr.parse()?))
    }

    /// Responds with whatever input is passed to it
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn echo(&self, s: &str) -> Result<String, Error> {
        const FOO: &str = "foo";

        let req =
            http_serde::echo::Request::new(HashMap::from([(FOO.into(), s.into())]), HashMap::new());
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        let status = resp.status();
        if status.is_success() {
            let result = hyper::body::to_bytes(resp.into_body()).await?;
            let http_serde::echo::Request {
                mut query_params, ..
            } = serde_json::from_slice(&result)?;
            query_params
                .remove(&String::from(FOO))
                .ok_or(Error::FailedRequest {
                    status,
                    reason: "did not receive mirrored response".into(),
                })
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    async fn resp_ok(resp: Response<Body>) -> Result<(), Error> {
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Intended to be called externally, e.g. by the report collector. Informs the MPC ring that
    /// the external party wants to start a new query.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn create_query(&self, data: QueryConfig) -> Result<QueryId, Error> {
        let req = http_serde::query::create::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            let body_bytes = body::to_bytes(resp.into_body()).await?;
            let http_serde::query::create::ResponseBody { query_id } =
                serde_json::from_slice(&body_bytes)?;
            Ok(query_id)
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }

    /// Used to communicate from one helper to another. Specifically, the helper that receives a
    /// "create query" from an external party must communicate the intent to start a query to the
    /// other helpers, which this prepare query does.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn prepare_query(
        &self,
        origin: HelperIdentity,
        data: PrepareQuery,
    ) -> Result<(), Error> {
        let req = http_serde::query::prepare::Request::new(origin, data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Intended to be called externally, e.g. by the report collector. After the report collector
    /// calls "create query", it must then send the data for the query to each of the clients. This
    /// query input contains the data intended for a helper.
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    pub async fn query_input(&self, data: QueryInput) -> Result<(), Error> {
        let req = http_serde::query::input::Request::new(data);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.streaming_client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Sends a batch of messages associated with a query's step to another helper. Messages are a
    /// contiguous block of records. Also includes [`crate::protocol::RecordId`] information and
    /// [`crate::helpers::network::ChannelId`].
    /// # Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// If messages size > max u32 (unlikely)
    pub async fn step(
        &self,
        origin: HelperIdentity,
        query_id: QueryId,
        step: &Step,
        payload: Vec<u8>,
        offset: u32,
    ) -> Result<(), Error> {
        let req =
            http_serde::query::step::Request::new(origin, query_id, step.clone(), payload, offset);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;
        let resp = self.client.request(req).await?;
        Self::resp_ok(resp).await
    }

    /// Wait for completion of the query and pull the results of this query. This is a blocking
    /// API so it is not supposed to be used outside of CLI context.
    ///
    /// ## Errors
    /// If the request has illegal arguments, or fails to deliver to helper
    /// # Panics
    /// if there is a problem reading the response body
    #[cfg(feature = "cli")]
    pub async fn query_results(&self, query_id: QueryId) -> Result<body::Bytes, Error> {
        let req = http_serde::query::results::Request::new(query_id);
        let req = req.try_into_http_request(self.scheme.clone(), self.authority.clone())?;

        let resp = self.client.request(req).await?;
        if resp.status().is_success() {
            Ok(body::to_bytes(resp.into_body()).await.unwrap())
        } else {
            Err(Error::from_failed_resp(resp).await)
        }
    }
}

// #[cfg(all(test, not(feature = "shuttle")))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::ff::FieldType;
    use crate::helpers::query::QueryType;
    use crate::helpers::CommandEnvelope;
    use crate::{
        net::{server::BindTarget, MpcHelperServer},
        sync::{Arc, Mutex},
    };
    use hyper_tls::native_tls::TlsConnector;
    use std::future::Future;
    use tokio::sync::mpsc;

    async fn setup_server(bind_target: BindTarget) -> (u16, mpsc::Receiver<CommandEnvelope>) {
        let (tx, rx) = mpsc::channel(1);
        let ongoing_queries = Arc::new(Mutex::new(HashMap::new()));
        let server = MpcHelperServer::new(tx, ongoing_queries);
        let (addr, _) = server.bind(bind_target).await;
        (addr.port(), rx)
    }

    async fn setup_server_http() -> (mpsc::Receiver<CommandEnvelope>, MpcHelperClient) {
        let (port, rx) = setup_server(BindTarget::Http("127.0.0.1:0".parse().unwrap())).await;
        let client = MpcHelperClient::with_str_addr(&format!("http://localhost:{}", port)).unwrap();
        (rx, client)
    }

    async fn setup_server_https() -> (mpsc::Receiver<CommandEnvelope>, MpcHelperClient) {
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (port, rx) =
            setup_server(BindTarget::Https("127.0.0.1:0".parse().unwrap(), config)).await;

        // requires custom client to use self signed certs
        let conn = TlsConnector::builder()
            .danger_accept_invalid_certs(true)
            .build()
            .unwrap();
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        let https = HttpsConnector::<HttpConnector>::from((http, conn.into()));
        let hyper_client = hyper::Client::builder().build(https.clone());
        let streaming_hyper_client = hyper::Client::builder().build(https);
        let client = MpcHelperClient {
            client: hyper_client,
            streaming_client: streaming_hyper_client,
            scheme: uri::Scheme::HTTPS,
            authority: uri::Authority::try_from(format!("localhost:{port}")).unwrap(),
        };

        (rx, client)
    }

    async fn test_http_https<Fut: Future<Output = ()>, F: Fn(MpcHelperClient) -> Fut>(f: F) {
        let (_, http_client) = setup_server_http().await;
        f(http_client).await;

        let (_, https_client) = setup_server_https().await;
        f(https_client).await;
    }

    #[tokio::test]
    async fn echo() {
        test_http_https(|client| async move {
            let expected_res = "echo-test";
            let res = client.echo(expected_res).await.unwrap();
            assert_eq!(res, expected_res);
        })
        .await;
    }

    #[tokio::test]
    async fn create() {
        test_http_https(|client| async move {
            let res = client
                .create_query(QueryConfig {
                    field_type: FieldType::Fp31,
                    query_type: QueryType::TestMultiply,
                })
                .await;
        })
        .await;
    }
}

/*
#[cfg(all(test, not(feature = "shuttle")))]
mod tests {
    use super::*;
    #[allow(deprecated)]
    use crate::{
        helpers::{
            http::HttpNetwork,
            network::{ChannelId, MessageChunks},
            old_network::Network,
            Role, MESSAGE_PAYLOAD_SIZE_BYTES,
        },
        net::{server::MessageSendMap, BindTarget, MpcHelperServer},
    };
    use futures::{Stream, StreamExt};
    use hyper_tls::native_tls::TlsConnector;

    #[allow(deprecated)]
    async fn setup_server(bind_target: BindTarget) -> (u16, impl Stream<Item = MessageChunks>) {
        let network = HttpNetwork::new_without_clients(QueryId, None);
        let rx_stream = network.recv_stream();
        let message_send_map = MessageSendMap::filled(network);
        let server = MpcHelperServer::new(message_send_map);
        // setup server
        let (addr, _) = server.bind(bind_target).await;
        (addr.port(), rx_stream)
    }

    async fn send_messages_req<St: Stream<Item = MessageChunks> + Unpin>(
        client: MpcHelperClient,
        mut rx_stream: St,
    ) {
        const DATA_LEN: u32 = 3;
        let query_id = QueryId;
        let step = Step::default().narrow("mul_test");
        let role = Role::H1;
        let offset = 0;
        let body = &[123; MESSAGE_PAYLOAD_SIZE_BYTES * (DATA_LEN as usize)];

        client
            .send_messages(HttpSendMessagesArgs {
                query_id,
                step: &step,
                offset,
                messages: Bytes::from_static(body),
            })
            .await
            .expect("send should succeed");

        let channel_id = ChannelId { role, step };
        let server_recvd = rx_stream.next().await.unwrap(); // should already have been received
        assert_eq!(server_recvd, (channel_id, body.to_vec()));
    }

    #[tokio::test]
    async fn send_messages_req_http() {
        let (port, rx_stream) =
            setup_server(BindTarget::Http("127.0.0.1:0".parse().unwrap())).await;

        // setup client
        let client =
            MpcHelperClient::with_str_addr(&format!("http://localhost:{port}"), Role::H1).unwrap();

        // test
        send_messages_req(client, rx_stream).await;
    }

    #[tokio::test]
    async fn send_messages_req_https() {
        let config = crate::net::server::tls_config_from_self_signed_cert()
            .await
            .unwrap();
        let (port, rx_stream) =
            setup_server(BindTarget::Https("127.0.0.1:0".parse().unwrap(), config)).await;

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
        let client = MpcHelperClient {
            role: Role::H1,
            client: hyper_client,
            scheme: uri::Scheme::HTTPS,
            authority: uri::Authority::try_from(format!("localhost:{port}")).unwrap(),
        };

        // test
        send_messages_req(client, rx_stream).await;
    }
}
 */
